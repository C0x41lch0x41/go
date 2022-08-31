// stellar-sign is a small interactive utility to help you contribute a
// signature to a transaction envelope or verify a transaction.
//
// It prompts you for a key, public (verify) or private (sign)
package main

import (
	"bufio"
	b64 "encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/network"

	"github.com/howeyc/gopass"
	"github.com/stellar/go/txnbuild"
	"github.com/stellar/go/xdr"
)

type SignOrVerify struct {
	verify  bool
	privKey *keypair.Full
	pubKey  *keypair.FromAddress
}

func (router *SignOrVerify) setKey(input string) {
	var err error
	if router.verify {
		inputPubKey, err := keypair.Parse(input)
		if err != nil {
			log.Fatal(err)
		}
		router.pubKey = inputPubKey.FromAddress()
	} else {
		router.privKey, err = keypair.ParseFull(input)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (router *SignOrVerify) do(gentx *txnbuild.GenericTransaction, networkPassphrase string) (string, error) {
	var newEnv string
	var err error
	if router.verify {
		var signature []byte
		var body []byte
		var gentxEnv xdr.TransactionEnvelope
		gentxEnv, err = gentx.ToXDR()
		if err != nil {
			log.Fatal(err)
		}
		signature = gentxEnv.Signatures()[0].Signature
		gentxHash, _ := gentx.Hash(networkPassphrase)
		body = gentxHash[:]
		err = router.pubKey.Verify(body, signature)
	} else {
		if tx, ok := gentx.Transaction(); ok {
			tx, err = tx.Sign(networkPassphrase, router.privKey)
			if err != nil {
				log.Fatal(err)
			}
			newEnv, err = tx.Base64()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			tx, _ := gentx.FeeBump()
			tx, err = tx.Sign(networkPassphrase, router.privKey)
			if err != nil {
				log.Fatal(err)
			}
			newEnv, err = tx.Base64()
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	return newEnv, err
}

var in *bufio.Reader

var infile = flag.String("infile", "", "transaction envelope")
var verify = flag.Bool("verify", false, "Verify the transaction instead of signing")
var testnet = flag.Bool("test", false, "Testnet")

func main() {
	flag.Parse()
	in = bufio.NewReader(os.Stdin)

	var (
		env string
		err error
	)

	if *infile == "" {
		// read envelope
		env, err = readLine("Enter envelope (base64): ", false)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		var file *os.File
		file, err = os.Open(*infile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		var raw []byte
		raw, err = ioutil.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}

		env = string(raw)
	}

	// parse the envelope
	var txe xdr.TransactionEnvelope
	err = xdr.SafeUnmarshalBase64(env, &txe)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("")
	fmt.Println("Transaction Summary:")
	sourceAccount := txe.SourceAccount().ToAccountId()
	fmt.Printf("  type: %s\n", txe.Type.String())
	fmt.Printf("  source: %s\n", sourceAccount.Address())
	fmt.Printf("  ops: %d\n", len(txe.Operations()))
	fmt.Printf("  sigs: %d\n", len(txe.Signatures()))
	for _, signature := range txe.Signatures() {
		fmt.Printf("    %s\n", b64.StdEncoding.EncodeToString(signature.Signature))
	}
	if txe.IsFeeBump() {
		fmt.Printf("  fee bump sigs: %d\n", len(txe.FeeBumpSignatures()))
	}
	fmt.Println("")

	// TODO: add operation details

	// read seed/public key
	key, err := readLine("Enter key", true)
	if err != nil {
		log.Fatal(err)
	}

	flowRouter := &SignOrVerify{verify: *verify}
	flowRouter.setKey(key)

	parsed, err := txnbuild.TransactionFromXDR(env)
	if err != nil {
		log.Fatal(err)
	}

	passPhrase := network.PublicNetworkPassphrase
	if *testnet {
		passPhrase = network.TestNetworkPassphrase
	}
	newEnv, err := flowRouter.do(parsed, passPhrase)
	if *verify {
		if err != nil {
			fmt.Print("\nSignature is INVALID\n")
		} else {
			fmt.Print("\nSignature is VALID\n")
		}
	} else {
		fmt.Print("\n==== Result ====\n\n")
		fmt.Print("```\n")
		fmt.Println(newEnv)
		fmt.Print("```\n")
	}

}

func readLine(prompt string, private bool) (string, error) {
	fmt.Println(prompt)
	var line string
	var err error

	if private {
		var str []byte
		str, err = gopass.GetPasswdMasked()
		if err != nil {
			return "", err
		}
		line = string(str)
	} else {
		line, err = in.ReadString('\n')
		if err != nil {
			return "", err
		}
	}
	return strings.Trim(line, "\n"), nil
}
