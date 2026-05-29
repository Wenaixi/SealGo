package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"SealGo"
	"SealGo/core"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "SealGo: %v\n", err)
		os.Exit(1)
	}
}

// Version is injected at build time via -ldflags="-X main.Version=X".
// Default "dev" indicates a non-release build.
var Version = "dev"

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}
	switch os.Args[1] {
	case "encrypt", "e":
		return doEncrypt(os.Args[2:])
	case "decrypt", "d":
		return doDecrypt(os.Args[2:])
	case "genpair":
		return doGenPair()
	case "version", "v":
		fmt.Println("SealGo " + Version)
		return nil
	default:
		printUsage()
		return nil
	}
}

func doEncrypt(args []string) error {
	fs := pflag.NewFlagSet("encrypt", pflag.ContinueOnError)
	input := fs.StringP("input", "i", "", "Input file (default stdin)")
	output := fs.StringP("output", "o", "", "Output file (default stdout)")
	fs.StringSliceP("recipient", "r", nil, "Recipient public key (hex, repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	recipients, _ := fs.GetStringSlice("recipient")
	if len(recipients) == 0 {
		return fmt.Errorf("at least one -r <recipient_hex> required")
	}
	recips := make([]core.Recipient, 0, len(recipients))
	for _, h := range recipients {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("invalid recipient key: %q", h)
		}
		var pub [32]byte
		copy(pub[:], b)
		recips = append(recips, &core.X25519Recipient{PubKey: pub})
	}
	inFile := openInput(*input)
	defer inFile.Close()
	outFile := openOutput(*output)
	defer outFile.Close()
	return SealGo.EncryptWithRecipients(outFile, inFile, recips, nil)
}

func doDecrypt(args []string) error {
	fs := pflag.NewFlagSet("decrypt", pflag.ContinueOnError)
	input := fs.StringP("input", "i", "", "Input file (default stdin)")
	output := fs.StringP("output", "o", "", "Output file (default stdout)")
	fs.StringSliceP("identity", "I", nil, "Identity private key (hex, repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	identities, _ := fs.GetStringSlice("identity")
	if len(identities) == 0 {
		return fmt.Errorf("at least one -I <identity_hex> required")
	}
	idents := make([]core.Identity, 0, len(identities))
	for _, h := range identities {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("invalid identity key: %q", h)
		}
		var priv [32]byte
		copy(priv[:], b)
		idents = append(idents, &core.X25519Identity{PrivKey: priv})
	}
	inFile := openInput(*input)
	defer inFile.Close()
	outFile := openOutput(*output)
	defer outFile.Close()
	return SealGo.DecryptWithIdentity(outFile, inFile, idents)
}

func doGenPair() error {
	pub, priv, err := SealGo.GenerateKeypair()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "public:  %x\nprivate: %x\n", pub, priv)
	return nil
}

func openInput(path string) *os.File {
	if path == "" || path == "-" {
		return os.Stdin
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SealGo: %v\n", err)
		os.Exit(1)
	}
	return f
}

func openOutput(path string) *os.File {
	if path == "" || path == "-" {
		return os.Stdout
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SealGo: %v\n", err)
		os.Exit(1)
	}
	return f
}

func printUsage() {
	fmt.Print(`SealGo - XChaCha20-Poly1305 multi-recipient encrypt/decrypt

USAGE:
  SealGo encrypt -r <pubkey_hex> [-i <in>] [-o <out>]
  SealGo decrypt -I <privkey_hex> [-i <in>] [-o <out>]
  SealGo genpair
  SealGo version

EXAMPLES:
  SealGo genpair
  SealGo encrypt -r <pubkey> -i data.bin -o data.sc
  SealGo decrypt -I <privkey> -i data.sc -o data.bin
`)
}