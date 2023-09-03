package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/golang-jwt/jwt/v5"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "gh-token",
		Usage: "Generate and manage GitHub App installation tokens",
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate a new GitHub App installation token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "app-id",
						Usage:    "GitHub App ID",
						Required: true,
						Aliases:  []string{"a"},
					},
					&cli.StringFlag{
						Name:     "installation-id",
						Usage:    "GitHub App ID",
						Required: true,
						Aliases:  []string{"i"},
					},
					&cli.StringFlag{
						Name:     "key",
						Usage:    "Path to private key",
						Required: false,
						Aliases:  []string{"k"},
					},
					&cli.StringFlag{
						Name:     "key-base64",
						Usage:    "A base64 encoded private key",
						Required: false,
						Aliases:  []string{"b"},
					},
					&cli.BoolFlag{
						Name:    "export-actions",
						Usage:   "Export token to the GITHUB_TOKEN environment variable by writing token to the GITHUB_ENV file",
						Aliases: []string{"e"},
						Value:   false,
					},
					&cli.StringFlag{
						Name:    "export-var-name",
						Usage:   "Override the default environment variable name to export the token to when using --export-actions",
						Aliases: []string{"v"},
						Value:   "GITHUB_TOKEN",
					},
					&cli.BoolFlag{
						Name:    "token-only",
						Usage:   "Only print the token to stdout, not the full JSON response, useful for piping to other commands",
						Aliases: []string{"o"},
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "silent",
						Usage:   "Do not print token to stdout",
						Aliases: []string{"s"},
						Value:   false,
					},
				},
				Action: run,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	appID := c.String("app-id")
	installationID := c.String("installation-id")
	keyPath := c.String("key")
	keyBase64 := c.String("key-base64")
	exportActions := c.Bool("export-actions")
	exportVarName := c.String("export-var-name")
	tokenOnly := c.Bool("token-only")
	silent := c.Bool("silent")

	if keyPath == "" && keyBase64 == "" {
		return fmt.Errorf("either --key or --key-base64 must be specified")
	}

	if keyPath != "" && keyBase64 != "" {
		return fmt.Errorf("only one of --key or --key-base64 may be specified")
	}

	var err error
	var privateKey *rsa.PrivateKey
	if keyPath != "" {
		privateKey, err = readKey(keyPath)
		if err != nil {
			return err
		}
	} else {
		privateKey, err = readKeyBase64(keyBase64)
		if err != nil {
			return err
		}
	}

	jsonWebToken, err := generateJWT(appID, privateKey)
	if err != nil {
		return fmt.Errorf("failed generating JWT: %w", err)
	}
	token, err := generateToken(jsonWebToken, installationID)
	if err != nil {
		return fmt.Errorf("failed generating installation token: %w", err)
	}

	if exportActions {
		exportVar := fmt.Sprintf("%s=%s\n", exportVarName, token.Value)

		envFile, exists := os.LookupEnv("GITHUB_ENV")
		if !exists {
			return fmt.Errorf("failed to export token, GITHUB_ENV environment variable not set")
		}
		f, err := os.OpenFile(envFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open GITHUB_ENV file: %w", err)
		}
		defer f.Close()

		_, err = f.WriteString(exportVar)
		if err != nil {
			return fmt.Errorf("failed to write to GITHUB_ENV file: %w", err)
		}
	}

	if !silent {
		bytes, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal token to JSON: %w", err)
		}

		if tokenOnly {
			fmt.Println(token.Value)
		} else {
			fmt.Println(string(bytes))
		}
	}

	return nil
}

func readKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read key file: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key from PEM to RSA format: %w", err)
	}

	return key, nil
}

func readKeyBase64(keyBase64 string) (*rsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key from base64: %w", err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key from PEM to RSA format: %w", err)
	}

	return key, nil
}

func generateJWT(appID string, key *rsa.PrivateKey) (string, error) {
	// One minute ago to account for clock skew
	sixtySecondsAgo := jwt.NewNumericDate(time.Now().Add(-60 * time.Second))
	// One minute in the future to limit the amount of time the token is valid
	oneMinuteInFuture := jwt.NewNumericDate(time.Now().Add(60 * time.Second))
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": sixtySecondsAgo,
		"exp": oneMinuteInFuture,
		"iss": appID,
	})
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT: %w", err)
	}

	return signedToken, nil
}

func generateToken(jwt, installationID string) (*tokenResponse, error) {
	client, err := api.NewRESTClient(api.ClientOptions{
		Headers: map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", jwt),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create REST client: %w", err)
	}
	var response *tokenResponse
	endpoint := fmt.Sprintf("app/installations/%s/access_tokens", installationID)
	err = client.Post(endpoint, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("unable to send POST request to %s: %w", endpoint, err)
	}

	return response, nil
}

type tokenResponse struct {
	Value     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}
