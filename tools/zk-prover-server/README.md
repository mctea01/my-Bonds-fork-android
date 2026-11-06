# zk-prover-server

A headless zkPDF prover for DIW Wallet (p4-zkp.md section 8, WP4 M4c). A phone that is too slow or short of
memory for a zkPDF proof can send the proof to a computer the holder runs. The server uses the same native library
and hash-pinned circuit assets as the desktop app.

## What the server sees

The wallet plans the proof on the phone and sends only the public statement and the private windows: the decoded
page content stream and the private image of the signed revision, plus the field salts. The server therefore sees
the text of page 1, not the rest of the PDF. The wallet asks for confirmation before it sends anything. The phone
verifies every returned segment against the statement it built with its own credential key; a result that does not
verify is discarded, so a modified server cannot make the wallet accept a false proof.

## Run

```sh
# Circuit assets (about 140 MB download, 400 MB installed), checked by SHA-256.
python3 -I native/circuits/tools/fetch_assets.py --output ~/zkpdf-assets
# Native library with the zkPDF backend, then the server distribution.
DIW_ZK_FEATURES=zkpdf ./gradlew :zk-prover-server:installDist -Pdiw.zkNative=require
export DIW_PROVER_TOKEN="$(openssl rand -base64 32)"
tools/zk-prover-server/build/install/zk-prover-server/bin/zk-prover-server --assets ~/zkpdf-assets --bind 0.0.0.0
```

The token needs at least 24 characters; enter the same token when adding the server in the wallet
(Settings, 零知識證明). Plain HTTP is accepted only for private-network addresses (10/8, 172.16/12, 192.168/16,
localhost, `.local`); for anything else put a TLS reverse proxy in front and use its `https://` address.
A proof needs about 2 GB of memory; one proof runs at a time and results are kept for one hour.

## API

All routes need `Authorization: Bearer <token>`.

| Route | Result |
|---|---|
| `POST /v1/zkpdf/jobs` | body: `ZkPdfProveRequest` JSON; `202 {"id"}`, `429` while another proof runs, `400` for a malformed request |
| `GET /v1/zkpdf/jobs/{id}` | `{"state": "queued" \| "running" \| "done" \| "failed" \| "cancelled", "kind", "done", "total", "result", "reason"}` |
| `DELETE /v1/zkpdf/jobs/{id}` | cancels a running proof or drops a finished result |
| `GET /v1/health` | `{"compositions": [...]}`: the compositions whose assets are complete |

The request and response formats are `ZkPdfRemote` in `core/src/commonMain/kotlin/diw/wallet/core/zk/ZkPdfRemote.kt`;
the same files are exchanged with the desktop app as `.zkpdfreq` and `.zkpdf` (Settings, 零知識證明, 代手機產生 zkPDF
證明 on the desktop; the phone exports the request from the derive screen and imports the proof on the file screen).
The phone asks for the desktop composition first and falls back to the phone composition, so installing the desktop
assets on the host is enough.
