package main

import (
	"fmt"
	"log"
	"os"

	"github.com/absfs/smbfs"
)

func main() {
	// Example 1: Connect to Windows file share with username/password
	// For advanced features like retry logic and logging, see examples/advanced/
	fsys, err := smbfs.New(&smbfs.Config{
		Server:   os.Getenv("SMB_SERVER"),   // e.g., "fileserver.corp.example.com"
		Share:    os.Getenv("SMB_SHARE"),    // e.g., "departments"
		Username: os.Getenv("SMB_USERNAME"), // e.g., "jdoe"
		Password: os.Getenv("SMB_PASSWORD"), // e.g., "secret123"
		Domain:   os.Getenv("SMB_DOMAIN"),   // e.g., "CORP" (optional)
		// Optional: Add RetryPolicy and Logger for production use
	})
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	// List files in root directory
	fmt.Println("Files in root directory:")
	entries, err := fsys.ReadDir("/")
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range entries {
		info, _ := entry.Info()
		fmt.Printf("%s %10d %s %s\n",
			info.Mode(),
			info.Size(),
			info.ModTime().Format("2006-01-02 15:04:05"),
			entry.Name())
	}

	// Example 2: Read a file
	fmt.Println("\nReading a file:")
	data, err := fsys.ReadFile("/README.txt")
	if err != nil {
		// File might not exist, that's okay for this example
		fmt.Printf("Could not read file: %v\n", err)
	} else {
		fmt.Printf("Read %d bytes\n", len(data))
		fmt.Printf("Content: %s\n", string(data))
	}

	// Example 3: Create a directory
	fmt.Println("\nCreating a directory:")
	err = fsys.MkdirAll("/test/example", 0755)
	if err != nil {
		fmt.Printf("Could not create directory: %v\n", err)
	} else {
		fmt.Println("Directory created successfully")
	}

	// Example 4: Write a file
	fmt.Println("\nWriting a file:")
	file, err := fsys.Create("/test/example/hello.txt")
	if err != nil {
		fmt.Printf("Could not create file: %v\n", err)
	} else {
		_, err = file.Write([]byte("Hello from smbfs!"))
		file.Close()
		if err != nil {
			fmt.Printf("Could not write file: %v\n", err)
		} else {
			fmt.Println("File written successfully")
		}
	}

	// Example 5: Stat a file
	fmt.Println("\nFile information:")
	info, err := fsys.Stat("/test/example/hello.txt")
	if err != nil {
		fmt.Printf("Could not stat file: %v\n", err)
	} else {
		fmt.Printf("Name: %s\n", info.Name())
		fmt.Printf("Size: %d bytes\n", info.Size())
		fmt.Printf("Mode: %s\n", info.Mode())
		fmt.Printf("Modified: %s\n", info.ModTime())
		fmt.Printf("IsDir: %v\n", info.IsDir())
	}

	// Example 6: Using connection string
	fmt.Println("\nUsing connection string:")
	connStr := fmt.Sprintf("smb://%s:%s@%s/%s",
		os.Getenv("SMB_USERNAME"),
		os.Getenv("SMB_PASSWORD"),
		os.Getenv("SMB_SERVER"),
		os.Getenv("SMB_SHARE"),
	)

	cfg, err := smbfs.ParseConnectionString(connStr)
	if err != nil {
		fmt.Printf("Could not parse connection string: %v\n", err)
	} else {
		fmt.Printf("Parsed config: Server=%s, Share=%s, Username=%s\n",
			cfg.Server, cfg.Share, cfg.Username)
	}
}
