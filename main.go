package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/Tnze/go-mc/chat"
	"github.com/go-mc/server/server"
	"github.com/go-mc/server/server/slp"
	"github.com/goccy/go-yaml"
)

func unwrap[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func main() {
	config := loadConfig()
	log.Println("Loading registry data...")
	registryMap := server.NewRegistryMap()
	for k, v := range config.RegistryData {
		readAll, err := os.ReadFile(v)
		if err != nil {
			log.Fatalf("Error reading registry data: %v", err)
		}
		registryMap.Put(k, readAll)
		log.Println("Loaded registry data for", k, "(size:"+strconv.Itoa(len(readAll)/1024)+"KiB)")
	}
	if len(config.RegistryData) == 0 {
		log.Println("WARNING: No registry data found, offline players may not authenticate.")
	}
	ctx := context.Background()
	serv := unwrap(server.NewServer(config, registryMap, ctx))

	log.Println("Starting server on", config.Listen)
	err := serv.Start()
	if err != nil {
		log.Fatalf("Error running server: %v", err)
	}
}

func loadConfig() *server.PortalConfig {
	config := &server.PortalConfig{
		Listen:          ":25565",
		FallbackServer:  "",
		CacheInvalidate: 60 * time.Second,
		Servers:         make(map[string]string),
		DefaultInfo: slp.ServerListPing{
			Version: slp.ServerVersion{
				Name:     "Error",
				Protocol: 0,
			},
			Players: slp.PlayerList{
				Max:    0,
				Online: 0,
				Sample: make([]slp.PlayerSample, 0),
			},
			Description: chat.Text("The requested Minecraft Server is currently offline.\nConsult the server administrator for more information."),
			FavIcon:     "",
		},
		DefaultSkin:  "e3RleHR1cmVzOntTS0lOOnt1cmw6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvODM3NmI4Y2RjZDUzM2YyNWI5NDlkOWU0MDYxYzM5ZDBlNWNjNTI2ZmJkYTBkZDBkMmI0YjVmNzgzZjIyMjJkZiJ9fX0=",
		AuthTimeout:  120 * time.Second,
		Keepalive:    15 * time.Second,
		RegistryData: make(map[int]string),
	}
	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		bytes := unwrap(yaml.Marshal(config))
		err := os.WriteFile("config.yaml", bytes, 0600)
		if err != nil {
			log.Fatalf("Error creating config.yaml: %v", err)
		}
		log.Println("Default configuration has been created.")
	} else {
		err := yaml.Unmarshal(unwrap(os.ReadFile("config.yaml")), config)
		if err != nil {
			panic(err)
		}
	}
	if config.AuthTimeout <= 0 {
		config.AuthTimeout = 120 * time.Second
	}
	if config.Keepalive <= 0 {
		config.Keepalive = 15 * time.Second
	}
	if config.CacheInvalidate <= 0 {
		config.CacheInvalidate = 60 * time.Second // not going to support on-demand fetch
	}
	if config.Servers == nil {
		panic("No servers configured")
	}
	if config.FallbackServer != "" {
		if _, ok := config.Servers[config.FallbackServer]; !ok {
			panic("Fallback server does not exist")
		}
	}
	return config
}
