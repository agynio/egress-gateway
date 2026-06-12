package egress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/enroll"
)

func EnsureZitiIdentity(identityFile string, enrollmentJWTFile string) error {
	if identityFile == "" {
		panic("ziti identity file is required")
	}
	if _, err := os.Stat(identityFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat ziti identity file: %w", err)
	}
	if enrollmentJWTFile == "" {
		return fmt.Errorf("ziti identity file %s does not exist and ZITI_ENROLLMENT_JWT_FILE is not set", identityFile)
	}
	jwtBytes, err := os.ReadFile(enrollmentJWTFile)
	if err != nil {
		return fmt.Errorf("read ziti enrollment jwt: %w", err)
	}
	claims, token, err := enroll.ParseToken(string(jwtBytes))
	if err != nil {
		return fmt.Errorf("parse ziti enrollment jwt: %w", err)
	}
	cfg, err := enroll.Enroll(enroll.EnrollmentFlags{Token: claims, JwtToken: token, JwtString: string(jwtBytes), KeyAlg: ziti.KeyAlgVar("EC")})
	if err != nil {
		return fmt.Errorf("enroll ziti identity: %w", err)
	}
	identityBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enrolled ziti identity: %w", err)
	}
	identityDir := filepath.Dir(identityFile)
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		return fmt.Errorf("create ziti identity directory: %w", err)
	}
	tempFile, err := os.CreateTemp(identityDir, ".identity-*.json")
	if err != nil {
		return fmt.Errorf("create temporary ziti identity file: %w", err)
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)
	if _, err := tempFile.Write(identityBytes); err != nil {
		tempFile.Close()
		return fmt.Errorf("write temporary ziti identity file: %w", err)
	}
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		return fmt.Errorf("chmod temporary ziti identity file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary ziti identity file: %w", err)
	}
	if err := os.Rename(tempName, identityFile); err != nil {
		return fmt.Errorf("install ziti identity file: %w", err)
	}
	return nil
}
