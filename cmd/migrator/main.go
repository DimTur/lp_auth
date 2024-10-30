package main

import (
	"fmt"
	"log"

	"github.com/DimTur/lp_auth/internal/config"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"
)

func ApplyMigrations() *cobra.Command {
	var (
		configPath     string
		migrationsPath string
	)

	c := &cobra.Command{
		Use:     "apply",
		Aliases: []string{"a"},
		Short:   "apply migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Parse(configPath)
			if err != nil {
				return fmt.Errorf("failed to parse config: %w", err)
			}

			uri := fmt.Sprintf(
				"mongodb://%s:%s@localhost:27017/%s?authSource=admin",
				cfg.Storage.UserName,
				cfg.Storage.Password,
				cfg.Storage.DbName,
			)

			m, err := migrate.New(
				"file://"+migrationsPath,
				uri,
			)
			if err != nil {
				return fmt.Errorf("failed to create migrate instance: %w", err)
			}
			defer m.Close()

			version, _, err := m.Version()
			if err != nil {
				if err.Error() == "no migration" {
					log.Println("No existing migrations found, applying new migrations.")
				} else {
					return fmt.Errorf("failed to get current migration version: %w", err)
				}
			} else {
				log.Printf("Current migration version: %d\n", version)
			}

			if err := m.Up(); err != nil {
				return fmt.Errorf("failed to apply migrations: %w", err)
			}

			newVersion, _, err := m.Version()
			if err != nil {
				return fmt.Errorf("failed to get new migration version: %w", err)
			}

			log.Printf("Migrations applied successfully. New migration version: %d\n", newVersion)

			return nil
		},
	}

	c.Flags().StringVar(&configPath, "config", "", "Path to config")
	c.Flags().StringVarP(&migrationsPath, "migrationsPath", "m", "", "Path to migrations") // Сокращение для флага
	c.MarkFlagRequired("config")
	c.MarkFlagRequired("migrationsPath")

	return c
}

func main() {
	cmd := ApplyMigrations()
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}
