@echo off
setlocal
set "DROIDSEAL_ROOT=%~dp0"
set "DROIDSEAL_DEPS=%DROIDSEAL_ROOT%dependencies"

if not exist "%DROIDSEAL_DEPS%\bundle-manifest.json" (
  echo [DroidSeal] Missing dependencies\bundle-manifest.json.
  echo Run: bun run bundle:local
  exit /b 1
)
if not exist "%DROIDSEAL_DEPS%\runtime\bun.exe" (
  echo [DroidSeal] Missing dependencies\runtime\bun.exe.
  exit /b 1
)

set "DROIDSEAL_BUNDLE_DIR=%DROIDSEAL_DEPS%"
set "JAVA_HOME=%DROIDSEAL_DEPS%\jdk"
set "ANDROID_SDK_ROOT=%DROIDSEAL_DEPS%\android-sdk"
set "ANDROID_HOME=%ANDROID_SDK_ROOT%"
set "NODE_PATH=%DROIDSEAL_DEPS%\node_modules"
set "PATH=%DROIDSEAL_DEPS%\runtime;%JAVA_HOME%\bin;%PATH%"

pushd "%DROIDSEAL_ROOT%"
"%DROIDSEAL_DEPS%\runtime\bun.exe" --preload "%DROIDSEAL_DEPS%\node_modules\@opentui\solid\scripts\preload.js" "%DROIDSEAL_ROOT%src\index.tsx" %*
set "DROIDSEAL_EXIT=%ERRORLEVEL%"
popd
exit /b %DROIDSEAL_EXIT%
