@echo off
rem Plafond : ouvre votre console (testnet-10). Le compte se cree ou souvre dans la page.
rem Vos fichiers restent dans le dossier "compte" a cote de ce fichier : ne le partagez pas.
cd /d "%~dp0"
if not exist vault-cli.exe (
  echo vault-cli.exe introuvable : placez-le dans ce dossier.
  pause
  exit /b 1
)
set PLAFOND_DOSSIER=%~dp0compte
vault-cli.exe plafond
pause
