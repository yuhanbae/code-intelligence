# CAN Diag Browser

Browser-based J1939 CAN bus frame decoder. No server needed - runs entirely in your browser.

## Usage

Open `index.html` in any browser:
1. Enter CAN ID (e.g. `0x18FEDB12`)
2. Enter data bytes (e.g. `E893000000000000`)
3. Click Decode
4. See decoded PGN, source/dest addresses, and field values

## Supported PGNs

50 J1939 PGNs including:
- Engine: RPM, coolant temp, oil pressure/temp, fuel rail pressure, turbo speed, EGT, torque
- Transmission: gear, shaft speeds, oil temp/pressure, torque converter slippage
- Brakes: system pressure, ABS status, wheel speed, trailer air
- Emissions: NOx, O2, DPF soot/ash/regen, EGR, SCR efficiency
- Vehicle: speed, fuel economy, runtime

## Live Demo

https://yuhanbae.github.io/can-diag-api/

## API Version

Server version available at:
https://github.com/yuhanbae/can-diag-api
