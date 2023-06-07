package network

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	consensusPretty "github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/connection"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/helpers"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"

	"github.com/oasisprotocol/cli/cmd/common"
	cliConfig "github.com/oasisprotocol/cli/config"
)

type propertySelector int

const (
	selInvalid propertySelector = iota
	selEntities
	selNodes
	selRuntimes
	selValidators
	selNativeToken
	selGasCosts
)

var showCmd = &cobra.Command{
	Use:     "show { <id> | entities | nodes | paratimes | validators | native-token | gas-costs }",
	Short:   "Show network properties",
	Long:    "Show network property stored in the registry, scheduler, genesis document or chain. Query by ID, hash or a specified kind.",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"s"},
	Run: func(cmd *cobra.Command, args []string) {
		cfg := cliConfig.Global()
		npa := common.GetNPASelection(cfg)

		id, err := parseIdentifier(npa, args[0])
		cobra.CheckErr(err)

		// Establish connection with the target network.
		ctx := context.Background()
		conn, err := connection.Connect(ctx, npa.Network)
		cobra.CheckErr(err)

		consensusConn := conn.Consensus()
		registryConn := consensusConn.Registry()

		// Figure out the height to use if "latest".
		height, err := common.GetActualHeight(
			ctx,
			consensusConn,
		)
		cobra.CheckErr(err)

		// This command just takes a brute-force "do-what-I-mean" approach
		// and queries everything it can till it finds what the user is
		// looking for.

		prettyPrint := func(b interface{}) error {
			data, err := json.MarshalIndent(b, "", "  ")
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", data)
			return nil
		}

		switch v := id.(type) {
		case signature.PublicKey:
			idQuery := &registry.IDQuery{
				Height: height,
				ID:     v,
			}

			if entity, err := registryConn.GetEntity(ctx, idQuery); err == nil {
				err = prettyPrint(entity)
				cobra.CheckErr(err)
				return
			}

			if nodeStatus, err := registryConn.GetNodeStatus(ctx, idQuery); err == nil {
				if node, err2 := registryConn.GetNode(ctx, idQuery); err2 == nil {
					err = prettyPrint(node)
					cobra.CheckErr(err)
				}

				err = prettyPrint(nodeStatus)
				cobra.CheckErr(err)
				return
			}

			nsQuery := &registry.GetRuntimeQuery{
				Height: height,
			}
			copy(nsQuery.ID[:], v[:])

			if runtime, err := registryConn.GetRuntime(ctx, nsQuery); err == nil {
				err = prettyPrint(runtime)
				cobra.CheckErr(err)
				return
			}
		case *types.Address:
			addr := staking.Address(*v)

			entities, err := registryConn.GetEntities(ctx, height)
			cobra.CheckErr(err) // If this doesn't work the other large queries won't either.
			for _, entity := range entities {
				if staking.NewAddress(entity.ID).Equal(addr) {
					err = prettyPrint(entity)
					cobra.CheckErr(err)
					return
				}
			}

			nodes, err := registryConn.GetNodes(ctx, height)
			cobra.CheckErr(err)
			for _, node := range nodes {
				if staking.NewAddress(node.ID).Equal(addr) {
					err = prettyPrint(node)
					cobra.CheckErr(err)
					return
				}
			}

			// Probably don't need to bother querying the runtimes by address.
		case propertySelector:
			switch v {
			case selEntities:
				entities, err := registryConn.GetEntities(ctx, height)
				cobra.CheckErr(err)
				for _, entity := range entities {
					err = prettyPrint(entity)
					cobra.CheckErr(err)
				}
				return
			case selNodes:
				nodes, err := registryConn.GetNodes(ctx, height)
				cobra.CheckErr(err)
				for _, node := range nodes {
					err = prettyPrint(node)
					cobra.CheckErr(err)
				}
				return
			case selRuntimes:
				runtimes, err := registryConn.GetRuntimes(ctx, &registry.GetRuntimesQuery{
					Height:           height,
					IncludeSuspended: true,
				})
				cobra.CheckErr(err)
				for _, runtime := range runtimes {
					err = prettyPrint(runtime)
					cobra.CheckErr(err)
				}
				return
			case selValidators:
				schedulerConn := consensusConn.Scheduler()
				validators, err := schedulerConn.GetValidators(ctx, height)
				cobra.CheckErr(err)
				for _, validator := range validators {
					err = prettyPrint(validator)
					cobra.CheckErr(err)
				}
				return
			case selNativeToken:
				stakingConn := consensusConn.Staking()
				showNativeToken(ctx, height, npa, stakingConn)
				return
			case selGasCosts:
				stakingConn := consensusConn.Staking()
				consensusParams, err := stakingConn.ConsensusParameters(ctx, height)
				cobra.CheckErr(err)

				fmt.Printf("Gas costs for network %s:", npa.PrettyPrintNetwork())
				fmt.Println()
				for kind, cost := range consensusParams.GasCosts {
					fmt.Printf("  - %-26s %d", kind+":", cost)
					fmt.Println()
				}
				return
			default:
				// Should never happen.
			}
		}

		cobra.CheckErr(fmt.Errorf("id '%s' not found", id))
	},
}

func parseIdentifier(
	npa *common.NPASelection,
	s string,
) (interface{}, error) { // TODO: Use `any`
	if sel := selectorFromString(s); sel != selInvalid {
		return sel, nil
	}

	addr, _, err := helpers.ResolveAddress(npa.Network, s)
	if err == nil {
		return addr, nil
	}

	var pk signature.PublicKey
	if err = pk.UnmarshalText([]byte(s)); err == nil {
		return pk, nil
	}
	if err = pk.UnmarshalHex(s); err == nil {
		return pk, nil
	}

	return nil, fmt.Errorf("unrecognized id: '%s'", s)
}

func selectorFromString(s string) propertySelector {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "entities":
		return selEntities
	case "nodes":
		return selNodes
	case "paratimes", "runtimes":
		return selRuntimes
	case "validators":
		return selValidators
	case "native-token":
		return selNativeToken
	case "gas-costs":
		return selGasCosts
	}
	return selInvalid
}

func showNativeToken(ctx context.Context, height int64, npa *common.NPASelection, stakingConn staking.Backend) {
	fmt.Printf("%-25s %s", "Network:", npa.PrettyPrintNetwork())
	fmt.Println()

	tokenSymbol, err := stakingConn.TokenSymbol(ctx)
	cobra.CheckErr(err)
	tokenValueExponent, err := stakingConn.TokenValueExponent(ctx)
	cobra.CheckErr(err)

	ctx = context.WithValue(
		ctx,
		consensusPretty.ContextKeyTokenSymbol,
		tokenSymbol,
	)
	ctx = context.WithValue(
		ctx,
		consensusPretty.ContextKeyTokenValueExponent,
		tokenValueExponent,
	)

	fmt.Printf("%-25s %s", "Token's ticker symbol:", tokenSymbol)
	fmt.Println()
	fmt.Printf("%-25s %d", "Token's base-10 exponent:", tokenValueExponent)
	fmt.Println()

	totalSupply, err := stakingConn.TotalSupply(ctx, height)
	cobra.CheckErr(err)
	fmt.Printf("%-25s ", "Total supply:")
	token.PrettyPrintAmount(ctx, *totalSupply, os.Stdout)
	fmt.Println()

	commonPool, err := stakingConn.CommonPool(ctx, height)
	cobra.CheckErr(err)
	fmt.Printf("%-25s ", "Common pool:")
	token.PrettyPrintAmount(ctx, *commonPool, os.Stdout)
	fmt.Println()

	lastBlockFees, err := stakingConn.LastBlockFees(ctx, height)
	cobra.CheckErr(err)
	fmt.Printf("%-25s ", "Last block fees:")
	token.PrettyPrintAmount(ctx, *lastBlockFees, os.Stdout)
	fmt.Println()

	governanceDeposits, err := stakingConn.GovernanceDeposits(ctx, height)
	cobra.CheckErr(err)
	fmt.Printf("%-25s ", "Governance deposits:")
	token.PrettyPrintAmount(ctx, *governanceDeposits, os.Stdout)
	fmt.Println()

	consensusParams, err := stakingConn.ConsensusParameters(ctx, height)
	cobra.CheckErr(err)

	fmt.Printf("%-25s %d epoch(s)", "Debonding interval:", consensusParams.DebondingInterval)
	fmt.Println()

	fmt.Println("\n=== STAKING THRESHOLDS ===")
	thresholdsToQuery := []staking.ThresholdKind{
		staking.KindEntity,
		staking.KindNodeValidator,
		staking.KindNodeCompute,
		staking.KindNodeKeyManager,
		staking.KindRuntimeCompute,
		staking.KindRuntimeKeyManager,
	}
	for _, kind := range thresholdsToQuery {
		threshold, err := stakingConn.Threshold(
			ctx,
			&staking.ThresholdQuery{
				Kind:   kind,
				Height: height,
			},
		)
		cobra.CheckErr(err)
		fmt.Printf("  %-19s ", kind.String()+":")
		token.PrettyPrintAmount(ctx, *threshold, os.Stdout)
		fmt.Println()
	}
}

func init() {
	showCmd.Flags().AddFlagSet(common.SelectorNFlags)
	showCmd.Flags().AddFlagSet(common.HeightFlag)
}
