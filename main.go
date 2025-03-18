package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "runtime"
    "strings"
    "time"

    "github.com/fatih/color"
)

// BANNER con ASCII art
var BANNER = `
   _____         __                  _______           __          
  / __(_)______ / /  ___ ____ ___   / ___/ /  ___ ____/ /_____ ____
 / _// / __/ -_) _ \/ _ '(_-</ -_) / /__/ _ \/ -_) __/  '_/ -_) __/
/_/ /_/_/  \__/_.__/\_,_/___/\__/  \___/_//_/\__/\__/_/\_\__/_/                                 

`

// Versión local del script
const SCRIPT_VERSION = "1.0.0"

// URL remoto donde está el script principal (para auto-update)
const REMOTE_SCRIPT_URL = "https://raw.githubusercontent.com/Suryesh/Firebase_Checker/main/firebase-checker.py"

// checkForUpdates compara la versión local con la remota y, si cambia, da la opción de reescribir main.go.
func checkForUpdates() {
    color.Blue("\nChecking for updates...")

    // Descargamos el script remoto
    resp, err := http.Get(REMOTE_SCRIPT_URL)
    if err != nil {
        color.Red("Failed to check for updates: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        color.Red("Failed to check for updates. HTTP status: %d", resp.StatusCode)
        return
    }

    // Leemos el contenido remoto
    remoteData, err := io.ReadAll(resp.Body)
    if err != nil {
        color.Red("Error reading remote script: %v", err)
        return
    }

    // Buscamos la línea con SCRIPT_VERSION en el archivo remoto
    var remoteVersion string
    lines := strings.Split(string(remoteData), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "SCRIPT_VERSION") {
            // Python style: SCRIPT_VERSION = "X.Y.Z"
            parts := strings.Split(line, "\"")
            if len(parts) >= 2 {
                remoteVersion = parts[1]
            }
            break
        }
    }

    if remoteVersion == "" {
        color.Red("Could not find remote script version.")
        return
    }

    if remoteVersion != SCRIPT_VERSION {
        color.Green("Update available: %s", remoteVersion)
        color.Yellow("Current version: %s", SCRIPT_VERSION)
        color.Yellow("Do you want to update? (y/n): ")

        input := readLine()
        if strings.ToLower(input) == "y" {
            // Intentamos sobrescribir el archivo .go actual
            currentFile := os.Args[0]

            // Si el script se está ejecutando con "go run main.go", os.Args[0] = path del binario temporal
            // Esto complica la auto-actualización. Intentamos heurística: buscar "main.go" en CWD
            if strings.HasSuffix(currentFile, "main.go") {
                // Directamente sobreescribimos
                err := os.WriteFile(currentFile, remoteData, 0644)
                if err == nil {
                    color.Green("Update successful! Please restart the script.")
                    os.Exit(0)
                } else {
                    color.Red("Failed to write updated script: %v", err)
                }
            } else {
                // Buscamos main.go en el mismo directorio actual
                // (Esta lógica se basa en que tu script se llame "main.go". Ajustar según convenga.)
                potentialFile := filepath.Join(".", "main.go")
                err := os.WriteFile(potentialFile, remoteData, 0644)
                if err != nil {
                    color.Red("Failed to write updated script: %v", err)
                } else {
                    color.Green("Update successful in main.go! Please restart using `go run main.go`.")
                    os.Exit(0)
                }
            }
        } else {
            color.Yellow("Update skipped.")
        }
    } else {
        color.Green("You are using the latest version.")
    }
}

// printBanner imprime el BANNER con color
func printBanner() {
    color.Cyan(BANNER)
}

// help muestra la ayuda
func help() {
    helpText := `
    This tool analyzes APK files for Firebase-related vulnerabilities, such as:
    - Open Firebase databases
    - Unauthorized Firebase signup
    - Firebase Remote Config misconfigurations

    Usage:
    -h, --help    (go run main.go -h)
    To Run        go run main.go
`
    color.Cyan(helpText)
}

// readLine lee una línea de texto desde stdin
func readLine() string {
    reader := bufio.NewReader(os.Stdin)
    line, _ := reader.ReadString('\n')
    return strings.TrimSpace(line)
}

// generateRandomEmail genera un email aleatorio
func generateRandomEmail() string {
    domains := []string{"gmail.com", "yahoo.com", "outlook.com", "protonmail.com"}
    rand.Seed(time.Now().UnixNano())
    username := strings.ReplaceAll(uuid(), "-", "")[:10]
    domain := domains[rand.Intn(len(domains))]
    return fmt.Sprintf("%s@%s", username, domain)
}

// uuid muy rudimentario sin usar librerías externas, o
// podrías usar google/uuid, por ejemplo. Aquí un stub:
func uuid() string {
    return fmt.Sprintf("%x-%x", rand.Uint64(), rand.Uint64())
}

// extractInfoFromApk corre `strings <apk>` y busca App ID, Firebase URL, y Google API Key
func extractInfoFromApk(apkPath string) (string, string, string) {
    // 1. Comprobamos que existe el archivo
    if _, err := os.Stat(apkPath); os.IsNotExist(err) {
        return "", "", ""
    }

    // 2. Ejecutamos strings <apkPath>
    cmd := exec.Command("strings", apkPath)
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        // Si falla, retornamos vacío
        return "", "", ""
    }
    stringsOutput := out.String()

    // 3. Regex
    reAppID := regexp.MustCompile(`1:(\d+):android:([a-f0-9]+)`)
    reFirebaseURL := regexp.MustCompile(`https://[a-zA-Z0-9-]+\.firebaseio\.com`)
    reGoogleAPIKey := regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)

    var appID, firebaseURL, googleAPIKey string
    if match := reAppID.FindString(stringsOutput); match != "" {
        appID = match
    }
    if match := reFirebaseURL.FindString(stringsOutput); match != "" {
        firebaseURL = match
    }
    if match := reGoogleAPIKey.FindString(stringsOutput); match != "" {
        googleAPIKey = match
    }
    return appID, firebaseURL, googleAPIKey
}

// sendAlert imprime un mensaje en rojo
func sendAlert(msg string) {
    color.Red("ALERT : %s", msg)
}

// executeCurlCommand ejecuta un comando curl en shell y muestra la salida
func executeCurlCommand(curlCmd string) string {
    color.Blue("\nExecuting: %s", curlCmd)
    // Usamos `bash -c` o `sh -c` según el sistema
    shell := "sh"
    shellFlag := "-c"
    if runtime.GOOS == "windows" {
        shell = "cmd"
        shellFlag = "/c"
    }

    cmd := exec.Command(shell, shellFlag, curlCmd)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    err := cmd.Run()
    output := out.String()

    color.Magenta("\nCurl Output:\n%s", output)

    if err != nil {
        color.Red("Error executing curl: %v", err)
    }
    return output
}

// checkFirebaseVulnerability similar a la función en Python
func checkFirebaseVulnerability(firebaseURL, googleAPIKey, appID, apkName string) []string {
    vulnerabilities := []string{}

    // 1. Chequear DB abierta
    if firebaseURL != "" {
        client := http.Client{Timeout: 5 * time.Second}
        resp, err := client.Get(fmt.Sprintf("%s/.json", firebaseURL))
        if err == nil {
            defer resp.Body.Close()
            if resp.StatusCode == 200 {
                vulnerabilities = append(vulnerabilities, "Open Firebase database detected")
                sendAlert(fmt.Sprintf("Open Firebase database detected in %s. URL: %s", apkName, firebaseURL))
                // ejecutar curl
                executeCurlCommand(fmt.Sprintf("curl %s/.json", firebaseURL))
            } else {
                vulnerabilities = append(vulnerabilities, "Firebase database is not openly accessible")
            }
        } else {
            vulnerabilities = append(vulnerabilities, "Failed to check Firebase database")
        }
    }

    // 2. Chequear Remote Config
    if googleAPIKey != "" && appID != "" {
        parts := strings.Split(appID, ":")
        if len(parts) >= 2 {
            projectID := parts[1]
            url := fmt.Sprintf("https://firebaseremoteconfig.googleapis.com/v1/projects/%s/namespaces/firebase:fetch?key=%s", projectID, googleAPIKey)
            body := map[string]string{
                "appId":         appID,
                "appInstanceId": "required_but_unused_value",
            }

            // Realizamos POST con net/http
            bodyJSON, _ := json.Marshal(body)
            client := http.Client{Timeout: 5 * time.Second}
            req, _ := http.NewRequest("POST", url, bytes.NewReader(bodyJSON))
            req.Header.Set("Content-Type", "application/json")
            resp, err := client.Do(req)
            if err != nil {
                vulnerabilities = append(vulnerabilities, fmt.Sprintf("Failed to check Firebase Remote Config: %v", err))
            } else {
                defer resp.Body.Close()
                if resp.StatusCode == 200 {
                    // parse JSON
                    var rbody map[string]interface{}
                    _ = json.NewDecoder(resp.Body).Decode(&rbody)
                    state, _ := rbody["state"].(string)
                    if state != "NO_TEMPLATE" {
                        vulnerabilities = append(vulnerabilities, "Firebase Remote Config is enabled")
                        sendAlert(fmt.Sprintf("Firebase Remote Config enabled in %s. URL: %s", apkName, url))

                        // Llamada "equivalente" de curl
                        _ = executeCurlCommand(fmt.Sprintf(
                            "curl -X POST '%s' -H 'Content-Type: application/json' -d '%s'",
                            url, string(bodyJSON),
                        ))
                    } else {
                        vulnerabilities = append(vulnerabilities, "Firebase Remote Config is disabled or inaccessible")
                    }
                } else {
                    vulnerabilities = append(vulnerabilities, "Firebase Remote Config is disabled or inaccessible")
                }
            }
        }
    }

    return vulnerabilities
}

// checkUnauthorizedSignup simula la creación de un usuario con Identity Toolkit
func checkUnauthorizedSignup(googleAPIKey, apkName string) []string {
    vulnerabilities := []string{}
    var idToken string

    if googleAPIKey != "" {
        signupURL := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", googleAPIKey)
        color.Yellow("Enter email for signup: ")
        userEmail := readLine()

        signupPayload := map[string]interface{}{
            "email":             userEmail,
            "password":          "Test@Pass123",
            "returnSecureToken": true,
        }
        spJSON, _ := json.Marshal(signupPayload)

        sendAlert(fmt.Sprintf("Testing unauthorized signup on %s", signupURL))
        response := executeCurlCommand(fmt.Sprintf("curl -X POST '%s' -H 'Content-Type: application/json' -d '%s'", signupURL, string(spJSON)))

        if strings.Contains(response, "idToken") {
            vulnerabilities = append(vulnerabilities, "Unauthorized Firebase signup is enabled")
            sendAlert("Unauthorized signup is enabled! This is a critical vulnerability.")

            // parse JSON
            var data map[string]interface{}
            _ = json.Unmarshal([]byte(response), &data)

            if val, ok := data["idToken"].(string); ok {
                idToken = val
            }
            if refreshToken, ok := data["refreshToken"].(string); ok {
                tokenURL := fmt.Sprintf("https://securetoken.googleapis.com/v1/token?key=%s", googleAPIKey)
                tokenPayload := map[string]string{
                    "grant_type":    "refresh_token",
                    "refresh_token": refreshToken,
                }
                tpJSON, _ := json.Marshal(tokenPayload)

                sendAlert("Fetching access token using refresh token...")
                executeCurlCommand(fmt.Sprintf("curl -X POST '%s' -H 'Content-Type: application/json' -d '%s'", tokenURL, string(tpJSON)))
            }
        }
    }

    if idToken != "" {
        lookupURL := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=%s", googleAPIKey)
        lookupPayload := map[string]string{"idToken": idToken}
        lpJSON, _ := json.Marshal(lookupPayload)

        sendAlert("Fetching account information using idToken...")
        executeCurlCommand(fmt.Sprintf("curl -X POST '%s' -H 'Content-Type: application/json' -d '%s'", lookupURL, string(lpJSON)))
    }
    return vulnerabilities
}

// processApks revisa si es un archivo individual o carpeta con varios .apk
func processApks(inputPath string) {
    // Convertimos la ruta a absoluta
    scriptDir, _ := os.Getwd()
    fullPath := filepath.Join(scriptDir, inputPath)

    fileInfo, err := os.Stat(fullPath)
    if err != nil {
        color.Red("Error: The path '%s' is not valid -> %v", fullPath, err)
        os.Exit(1)
    }

    var apkFiles []string
    if fileInfo.IsDir() {
        entries, _ := os.ReadDir(fullPath)
        for _, e := range entries {
            if !e.IsDir() && strings.HasSuffix(e.Name(), ".apk") {
                apkFiles = append(apkFiles, filepath.Join(fullPath, e.Name()))
            }
        }
    } else {
        // Si es un archivo .apk
        if strings.HasSuffix(fullPath, ".apk") {
            apkFiles = append(apkFiles, fullPath)
        } else {
            color.Red("Error: '%s' is not an .apk file.", fullPath)
            os.Exit(1)
        }
    }

    if len(apkFiles) == 0 {
        color.Red("No APK files found in '%s'.", fullPath)
        os.Exit(1)
    }

    // Procesamos cada .apk
    for _, apkPath := range apkFiles {
        fileName := filepath.Base(apkPath)
        color.Cyan("\nProcessing APK: %s", fileName)

        appID, firebaseURL, googleAPIKey := extractInfoFromApk(apkPath)

        color.Green("App ID: %s", orEmpty(appID, "None"))
        color.Green("Firebase URL: %s", orEmpty(firebaseURL, "None"))
        color.Green("Google API Key: %s", orEmpty(googleAPIKey, "None"))

        vulnerabilities := checkFirebaseVulnerability(firebaseURL, googleAPIKey, appID, fileName)
        su := checkUnauthorizedSignup(googleAPIKey, fileName)
        vulnerabilities = append(vulnerabilities, su...)

        color.Yellow("\nVulnerability Check Results:")
        for _, v := range vulnerabilities {
            if strings.Contains(v, "detected") || strings.Contains(v, "enabled") {
                color.Red("- %s", v)
            } else {
                color.Green("- %s", v)
            }
        }
    }
}

func orEmpty(v string, def string) string {
    if v == "" {
        return def
    }
    return v
}

func main() {
    // Si pasamos -h o --help, mostramos ayuda
    if len(os.Args) >= 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
        printBanner()
        help()
        os.Exit(0)
    }

    // Primero, check updates
    checkForUpdates()

    // Banner
    printBanner()

    // Preguntamos al usuario la ruta del APK o carpeta
    color.Yellow("Enter the path to the APK file or folder containing APKs: ")
    inputPath := readLine()

    // Procesamos
    processApks(inputPath)
}
