package main

import (
        "flag"
        "fmt"
        "log"
        "os"
        "path"
        "path/filepath"
        "strconv"
	"time"
        "github.com/HenriqueLockem/lockEM-LATO-SBS/funcs"
	"encoding/json"


)

const (
        // constVersion Version
        constVersion = "1.1"
        // constProcDir default /proc dir for processes.
        constProcDir = "/proc"
        // constDelimeterDefault default delimiter for CSV output.
        constDelimeterDefault = ","
        // constMinPID minimum PID value allowed for process checks.
        constMinPID = 1
        // constMaxPID maximum PID value allowed for process checks. 64bit linux is 2^22. This value is a limiter.
        constMaxPID = 4194304
)

type fileData struct {
 	Name    string  `json:"name"`
        Path    string  `json:"path"`
        Entropy float64 `json:"entropy"`
        Elf     bool    `json:"suspect"`
        Hash    hashes  `json:"hash"`
}


type hashes struct {
        Md5    string `json:"md5"`
        Sha1   string `json:"sha1"`
        Sha256 string `json:"sha256"`
        SSDeep string `json:"ssdeep"`
}

func main() {
        
	start := time.Now()
	var analyzedFiles int
	var filePath string
        var dirPath string
        var delimChar string
        var entropyMaxVal float64
        var elfOnly bool
        var procOnly bool
        var csvOutput bool
        var version bool

	analyzedFiles = 0

        flag.StringVar(&filePath, "file", "", "full path to a single file to analyze")
        flag.StringVar(&dirPath, "dir", "", "directory name to analyze")
        flag.StringVar(&delimChar, "delim", constDelimeterDefault, "delimeter for CSV output")
        flag.Float64Var(&entropyMaxVal, "entropy", 0, "show any file with entropy greater than or equal to this value (0.0 - 8.0 max 8.0, default is 0)")
        flag.BoolVar(&elfOnly, "elf", false, "only check suspicious files")
        flag.BoolVar(&procOnly, "proc", false, "check running processes")
        flag.BoolVar(&csvOutput, "csv", false, "output results in CSV format (filename, path, entropy, suspicious files [true|false])")
        flag.BoolVar(&version, "version", false, "show version and exit")
        flag.Parse()

        if version {
                fmt.Printf("LockEM LATO Cloud Agent Version %s\n", constVersion)
                fmt.Printf("Copyright (c) 2024 LockEM - www.lockem.tech\n\n")
                os.Exit(0)
        }

        if entropyMaxVal > 8 {
                log.Fatal("max entropy value is 8.0")
        }
        if entropyMaxVal < 0 {
                log.Fatal("min entropy value is 0.0")
        }
 if procOnly {
                if os.Geteuid() != 0 {
                        log.Fatalf("process checking option requires UID/EUID 0 (root) to run")
                }
                // This will do a PID bust of all PID range to help detect hidden PIDs.
                pidPaths, err := genPIDExePaths()
                if err != nil {
                        log.Fatalf("error generating PID list: %v\n", err)
                }
                for pid := 0; pid < len(pidPaths); pid++ {
                        // Only check elf files which should be all these will be anyway.
                        fileInfo, err := checkFilePath(pidPaths[pid], true, entropyMaxVal)
                        // anything that is not an error is a valid /proc/*/exe link we could see and process. We will analyze it.
                        if err == nil {
                                if fileInfo.entropy >= entropyMaxVal {
                                        printResults(fileInfo, csvOutput, delimChar)
                                }
                        }
                }
                os.Exit(0)
        }

        if filePath != "" {
                fileInfo, err := checkFilePath(filePath, elfOnly, entropyMaxVal)
                if err != nil {
                        log.Fatalf("error processing file (%s): %v\n", filePath, err)
                }

                if fileInfo.entropy >= entropyMaxVal {
                        printResults(fileInfo, csvOutput, delimChar)
	                printJSONResults(fileInfo)
			analyzedFiles++        
        }

                os.Exit(0)
        }
  if dirPath != "" {
                var search = func(filePath string, info os.FileInfo, err error) error {
                        if err != nil {
                                log.Fatalf("error walking directory (%s) inside search function: %v\n", filePath, err)
                        }
                        // If info comes back as nil we don't want to read it or we panic.
                        if info != nil {
                                // if not a directory, then check it for a file we want.
                                if !info.IsDir() {
                                        // Only check regular files. Checking devices, etc. won't work.
                                        if info.Mode().IsRegular() {
                                                fileInfo, err := checkFilePath(filePath, elfOnly, entropyMaxVal)
                                                if err != nil {
                                                        log.Fatalf("error processing file (%s): %v\n", filePath, err)
                                                }

                                                if fileInfo.entropy >= entropyMaxVal {
                                                        printResults(fileInfo, csvOutput, delimChar)
							printJSONResults(fileInfo)
       							analyzedFiles++                
	                         }
                                        }
                                }
                        }
                        return nil
                }
                err := filepath.Walk(dirPath, search)
                if err != nil {
                        log.Fatalf("error walking directory (%s): %v\n", dirPath, err)
                }
                elapsed :=time.Since(start)
        	fmt.Printf("Analyzed %v files in %s\n", analyzedFiles, elapsed) 

		os.Exit(0)
        }

}

// Function to print results in JSON format
func printJSONResults(fileInfo fileData) {
        jsonData, err := json.Marshal(fileInfo)
        if err != nil {
                log.Println("Error marshalling JSON: %v\n", err)
        }
            fmt.Println(string(jsonData))


}

// Prints results
func printResults(fileInfo fileData, csvFormat bool, delimChar string) {
//        if !csvFormat {
//                fmt.Printf("filename: %s\npath: %s\nentropy: %.2f\nExecutable_Detected:  %v\nmd5: %s\nsha1: %s\nsha256: %s\nsha512: %s\n\n",
//                        fileInfo.name,
//                        fileInfo.path,
//                        fileInfo.entropy,
//                        fileInfo.elf,
//			fileInfo.hash.md5,
//			fileInfo.hash.sha1,
//			fileInfo.hash.sha256,
//			fileInfo.hash.sha512)
//        } else {
	if csvFormat{ 
                fmt.Printf("%s%s%s%s%.2f%s%v%s%s%s%s%s%s%s%s\n",
                        fileInfo.name,
                        delimChar,
                        fileInfo.path,
                        delimChar,
                        fileInfo.entropy,
                        delimChar,
                        fileInfo.elf
			delimChar,
			fileInfo.hash.md5,
			delimChar,
			fileInfo.hash.sha1,
			delimChar,
			fileInfo.hash.sha256,
			delimChar,
			fileInfo.hash.sha512)
	 }
}


func checkFilePath(filePath string, elfOnly bool, entropyMaxVal float64) (fileInfo fileData, err error) {
        isElfType, err := funcs.IsElfType(filePath)
        if err != nil {
                return fileInfo, err
        }
        _, fileName := filepath.Split(filePath)

        fileInfo.path = filePath
        fileInfo.name = fileName
        fileInfo.elf = isElfType
        fileInfo.entropy = -1

        // If they only want Linux ELFs.
        if elfOnly && isElfType {
                entropy, err := funcs.Entropy(filePath)
                if err != nil {
                        log.Fatalf("error calculating entropy for file (%s): %v\n", filePath, err)
                }
                fileInfo.entropy = entropy
        }
        // They want entropy on all files.
        if !elfOnly {
                entropy, err := funcs.Entropy(filePath)
                if err != nil {
                        log.Fatalf("error calculating entropy for file (%s): %v\n", filePath, err)
                }
                fileInfo.entropy = entropy
        }
	if fileInfo.entropy >= entropyMaxVal {
		md5, err := funcs.HashMD5(filePath)
		if err != nil {
			log.Fatalf("error calculating MD5 hash for file (%s): %v\n", filePath, err)
		}
		sha1, err := funcs.HashSHA1(filePath)
		if err != nil {
			log.Fatalf("error calculating SHA1 hash for file (%s): %v\n", filePath, err)
		}
		sha256, err := funcs.HashSHA256(filePath)
		if err != nil {
			log.Fatalf("error calculating SHA256 hash for file (%s): %v\n", filePath, err)
		}
		ssdeep, err := funcs.SSDeepHash(filePath)
		if err != nil {
			log.Fatalf("error calculating SSDeep hash for file (%s): %v\n", filePath, err)
		}
		fileInfo.hash.md5 = md5
		fileInfo.hash.sha1 = sha1
		fileInfo.hash.sha256 = sha256
		fileInfo.hash.SSDeep = ssdeep
	}

        return fileInfo, nil
}

func genPIDExePaths() (pidPaths []string, err error) {

        for pid := constMinPID; pid < constMaxPID; pid++ {
                pidPaths = append(pidPaths, path.Join(constProcDir, strconv.Itoa(pid), "/exe"))
        }

        return pidPaths, nil
}

        
