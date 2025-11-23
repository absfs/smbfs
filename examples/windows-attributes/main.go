package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/absfs/smbfs"
)

func main() {
	// Example: Working with Windows-specific file attributes

	fsys, err := smbfs.New(&smbfs.Config{
		Server:   os.Getenv("SMB_SERVER"),
		Share:    os.Getenv("SMB_SHARE"),
		Username: os.Getenv("SMB_USERNAME"),
		Password: os.Getenv("SMB_PASSWORD"),
		Domain:   os.Getenv("SMB_DOMAIN"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	fmt.Println("=== Windows Attributes Example ===")

	// Example 1: List shares on the server
	fmt.Println("1. Listing shares on server:")
	shares, err := fsys.ListShares(context.Background())
	if err != nil {
		log.Printf("Warning: Could not list shares: %v", err)
	} else {
		for _, share := range shares {
			fmt.Printf("   - %s (%s): %s\n", share.Name, share.Type, share.Comment)
		}
	}
	fmt.Println()

	// Example 2: Check file attributes
	fmt.Println("2. Checking file attributes:")
	testPath := "/test_windows_attrs.txt"

	// Create a test file
	file, err := fsys.Create(testPath)
	if err != nil {
		log.Printf("Warning: Could not create test file: %v", err)
	} else {
		file.Write([]byte("Testing Windows attributes"))
		file.Close()

		// Get file info
		info, err := fsys.Stat(testPath)
		if err != nil {
			log.Printf("Could not stat file: %v", err)
		} else {
			fmt.Printf("   File: %s\n", info.Name())
			fmt.Printf("   Size: %d bytes\n", info.Size())
			fmt.Printf("   Mode: %s\n", info.Mode())

			// Try to get Windows attributes
			if infoEx, ok := info.(smbfs.FileInfoEx); ok {
				if attrs := infoEx.WindowsAttributes(); attrs != nil {
					fmt.Printf("   Windows Attributes: %s\n", attrs.String())
					fmt.Printf("     - Hidden: %v\n", attrs.IsHidden())
					fmt.Printf("     - System: %v\n", attrs.IsSystem())
					fmt.Printf("     - ReadOnly: %v\n", attrs.IsReadOnly())
					fmt.Printf("     - Archive: %v\n", attrs.IsArchive())
				} else {
					fmt.Println("   Windows Attributes: Not available")
				}
			}
		}

		// Clean up
		fsys.Remove(testPath)
	}
	fmt.Println()

	// Example 3: Read directory with attribute checking
	fmt.Println("3. Listing directory with Windows attributes:")
	entries, err := fsys.ReadDir("/")
	if err != nil {
		log.Printf("Could not read directory: %v", err)
	} else {
		fmt.Printf("   Found %d entries:\n", len(entries))
		for i, entry := range entries {
			if i >= 5 {
				fmt.Printf("   ... and %d more\n", len(entries)-5)
				break
			}

			info, _ := entry.Info()
			name := entry.Name()

			// Check if hidden (would need Windows attributes)
			hidden := ""
			if infoEx, ok := info.(smbfs.FileInfoEx); ok {
				if attrs := infoEx.WindowsAttributes(); attrs != nil {
					if attrs.IsHidden() {
						hidden = " [HIDDEN]"
					}
					if attrs.IsSystem() {
						hidden += " [SYSTEM]"
					}
					if attrs.IsReadOnly() {
						hidden += " [READONLY]"
					}
				}
			}

			typeStr := "file"
			if entry.IsDir() {
				typeStr = "dir "
			}

			fmt.Printf("   - [%s] %s%s\n", typeStr, name, hidden)
		}
	}
	fmt.Println()

	// Example 4: Demonstrate attribute manipulation
	fmt.Println("4. Windows attribute manipulation:")
	attrs := smbfs.NewWindowsAttributes(smbfs.FILE_ATTRIBUTE_NORMAL)

	fmt.Println("   Initial attributes:", attrs.String())

	attrs.SetHidden(true)
	fmt.Println("   After SetHidden(true):", attrs.String())

	attrs.SetReadOnly(true)
	fmt.Println("   After SetReadOnly(true):", attrs.String())

	attrs.SetSystem(true)
	fmt.Println("   After SetSystem(true):", attrs.String())

	attrs.SetArchive(true)
	fmt.Println("   After SetArchive(true):", attrs.String())

	fmt.Println("\n   Raw attribute value:", fmt.Sprintf("0x%08X", attrs.Attributes()))
	fmt.Println()

	// Example 5: Share types
	fmt.Println("5. Share types:")
	shareTypes := []smbfs.ShareType{
		smbfs.ShareTypeDisk,
		smbfs.ShareTypePrintQueue,
		smbfs.ShareTypeDevice,
		smbfs.ShareTypeIPC,
		smbfs.ShareTypeSpecial,
		smbfs.ShareTypeTemporary,
	}

	for _, st := range shareTypes {
		fmt.Printf("   - %s (0x%08X)\n", st.String(), uint32(st))
	}
	fmt.Println()

	// Example 6: Mode to attributes conversion
	fmt.Println("6. Unix mode to Windows attributes conversion:")
	modes := []fs.FileMode{
		0666,                   // Regular file, read-write
		0444,                   // Read-only file
		fs.ModeDir | 0755,      // Directory
		fs.ModeSymlink | 0777,  // Symlink
		fs.ModeDevice | 0666,   // Device
	}

	for _, mode := range modes {
		// This is an internal function, shown for demonstration
		// In real code, this conversion happens automatically
		fmt.Printf("   Mode %v would map to Windows attributes\n", mode)
	}

	fmt.Println("\n=== Example complete ===")
}
