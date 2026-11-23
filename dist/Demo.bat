@echo off
rem Demo de bout en bout sur testnet-10, cles jetables (aucun argent reel).
cd /d "%~dp0"
if not defined NOEUD_WRPC set NOEUD_WRPC=wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
vault-cli.exe demo
pause
