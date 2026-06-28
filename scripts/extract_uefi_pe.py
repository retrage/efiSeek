#!/usr/bin/env python3
import argparse
import binascii
import csv
import hashlib
import lzma
import struct
import uuid
import zlib
from pathlib import Path


FV_SIGNATURE = b"_FVH"

FILE_TYPES = {
    0x01: "Raw",
    0x02: "Freeform",
    0x03: "SecurityCore",
    0x04: "PeiCore",
    0x05: "DxeCore",
    0x06: "Peim",
    0x07: "Driver",
    0x08: "CombinedPeimDriver",
    0x09: "Application",
    0x0A: "Smm",
    0x0B: "FirmwareVolumeImage",
    0x0C: "CombinedSmmDxe",
    0x0D: "SmmCore",
    0x0E: "SmmStandalone",
    0x0F: "SmmCoreStandalone",
}

SECTION_TYPES = {
    0x01: "Compression",
    0x02: "GuidDefined",
    0x10: "Pe32",
    0x11: "Pic",
    0x12: "Te",
    0x13: "DxeDepex",
    0x14: "Version",
    0x15: "Ui",
    0x16: "Compatibility16",
    0x17: "FirmwareVolumeImage",
    0x18: "FreeformSubtypeGuid",
    0x19: "Raw",
    0x1B: "PeiDepex",
    0x1C: "SmmDepex",
}


def align(value, boundary):
    return (value + boundary - 1) & ~(boundary - 1)


def u24(buf):
    return buf[0] | (buf[1] << 8) | (buf[2] << 16)


def guid_from_bytes(raw):
    return str(uuid.UUID(bytes_le=raw)).upper()


def safe_name(value):
    if not value:
        return "noname"
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value)[:120]


def decode_ui(data):
    raw = data.rstrip(b"\x00")
    if not raw:
        return ""
    return raw.decode("utf-16le", errors="ignore").rstrip("\x00")


def decompress_candidates(payload):
    out = []
    for fmt_name, fmt in (("lzma-alone", lzma.FORMAT_ALONE), ("lzma-auto", lzma.FORMAT_AUTO)):
        try:
            out.append((fmt_name, lzma.decompress(payload, format=fmt)))
        except lzma.LZMAError:
            pass
    try:
        out.append(("zlib", zlib.decompress(payload)))
    except zlib.error:
        pass
    return out


class Extractor:
    def __init__(self, out_dir):
        self.out_dir = Path(out_dir)
        self.pe_dir = self.out_dir / "pe"
        self.te_dir = self.out_dir / "te"
        self.fv_dir = self.out_dir / "fv"
        self.pe_dir.mkdir(parents=True, exist_ok=True)
        self.te_dir.mkdir(parents=True, exist_ok=True)
        self.fv_dir.mkdir(parents=True, exist_ok=True)
        self.rows = []
        self.fvs_seen = set()
        self.counter = 0

    def parse_all_fvs(self, data, base_offset=0):
        pos = 0
        while True:
            idx = data.find(FV_SIGNATURE, pos)
            if idx < 0:
                return
            start = idx - 40
            if start >= 0:
                self.parse_fv(data, start, base_offset + start)
            pos = idx + 4

    def parse_fv(self, data, start, abs_start):
        if abs_start in self.fvs_seen:
            return
        if start < 0 or start + 0x38 > len(data):
            return
        if data[start + 40:start + 44] != FV_SIGNATURE:
            return
        fv_len = struct.unpack_from("<Q", data, start + 32)[0]
        hdr_len = struct.unpack_from("<H", data, start + 48)[0]
        if fv_len < hdr_len or fv_len > len(data) - start:
            return
        self.fvs_seen.add(abs_start)
        fv = data[start:start + fv_len]
        fv_guid = guid_from_bytes(data[start + 16:start + 32])
        (self.fv_dir / f"fv_{abs_start:08X}_{fv_guid}.bin").write_bytes(fv)

        off = align(hdr_len, 8)
        while off + 24 <= len(fv):
            header = fv[off:off + 24]
            if header in (b"\xff" * 24, b"\x00" * 24):
                off += 8
                continue
            size = u24(header[20:23])
            header_size = 24
            if size == 0xFFFFFF:
                if off + 32 > len(fv):
                    break
                size = struct.unpack_from("<Q", fv, off + 24)[0]
                header_size = 32
            if size < header_size or off + size > len(fv):
                off += 8
                continue
            ctx = {
                "fv_offset": abs_start,
                "ffs_guid": guid_from_bytes(header[:16]),
                "ffs_type": FILE_TYPES.get(header[18], f"File{header[18]:02X}"),
                "ui": "",
                "section_path": [],
            }
            self.parse_sections(fv[off + header_size:off + size], ctx)
            off = align(off + size, 8)

    def parse_sections(self, data, ctx):
        ui = self.find_ui(data)
        if ui:
            ctx = {**ctx, "ui": ui}

        off = 0
        parsed = False
        while off + 4 <= len(data):
            size = u24(data[off:off + 3])
            sec_type = data[off + 3]
            hdr_len = 4
            if size == 0xFFFFFF:
                if off + 8 > len(data):
                    break
                size = struct.unpack_from("<I", data, off + 4)[0]
                hdr_len = 8
            if size < hdr_len or off + size > len(data):
                break
            parsed = True
            payload = data[off + hdr_len:off + size]
            sec_name = SECTION_TYPES.get(sec_type, f"Section{sec_type:02X}")
            next_ctx = {**ctx, "section_path": ctx["section_path"] + [sec_name]}
            if sec_type == 0x10:
                self.write_image("PE32", payload, next_ctx)
            elif sec_type == 0x12:
                self.write_image("TE", payload, next_ctx)
            elif sec_type == 0x17:
                self.parse_all_fvs(payload, ctx["fv_offset"])
            elif sec_type == 0x01 and len(payload) >= 5:
                comp = payload[5:]
                for method, blob in decompress_candidates(comp):
                    self.parse_sections(blob, {**next_ctx, "section_path": next_ctx["section_path"] + [method]})
                    self.parse_all_fvs(blob, ctx["fv_offset"])
            elif sec_type == 0x02 and len(payload) >= 20:
                data_offset = struct.unpack_from("<H", payload, 16)[0]
                guided = data[off + data_offset:off + size] if data_offset >= hdr_len else payload[20:]
                for method, blob in decompress_candidates(guided):
                    self.parse_sections(blob, {**next_ctx, "section_path": next_ctx["section_path"] + [method]})
                    self.parse_all_fvs(blob, ctx["fv_offset"])
            off = align(off + size, 4)

        if not parsed:
            self.parse_all_fvs(data, ctx["fv_offset"])

    def write_image(self, kind, payload, ctx):
        self.counter += 1
        ui = safe_name(ctx["ui"])
        sec_path = ".".join(ctx["section_path"])
        suffix = "efi" if kind == "PE32" else "te"
        filename = f"{self.counter:04d}_fv{ctx['fv_offset']:08X}_{ctx['ffs_guid']}_{ui}_{safe_name(sec_path)}.{suffix}"
        target = (self.pe_dir if kind == "PE32" else self.te_dir) / filename
        target.write_bytes(payload)
        self.rows.append({
            "kind": kind,
            "path": str(target),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "fv_offset": f"0x{ctx['fv_offset']:X}",
            "ffs_guid": ctx["ffs_guid"],
            "ffs_type": ctx["ffs_type"],
            "ui": ctx["ui"],
            "section_path": sec_path,
        })

    @staticmethod
    def find_ui(data):
        off = 0
        while off + 4 <= len(data):
            size = u24(data[off:off + 3])
            sec_type = data[off + 3]
            hdr_len = 4
            if size == 0xFFFFFF:
                if off + 8 > len(data):
                    return ""
                size = struct.unpack_from("<I", data, off + 4)[0]
                hdr_len = 8
            if size < hdr_len or off + size > len(data):
                return ""
            if sec_type == 0x15:
                return decode_ui(data[off + hdr_len:off + size])
            off = align(off + size, 4)
        return ""

    def scan_raw_lzma(self, data):
        pos = 0
        while True:
            idx = data.find(b"\x5d\x00\x00\x00\x01", pos)
            if idx < 0:
                return
            for method, blob in decompress_candidates(data[idx:]):
                self.parse_sections(blob, {
                    "fv_offset": idx,
                    "ffs_guid": "RAW_LZMA",
                    "ffs_type": "RawCompressed",
                    "ui": "",
                    "section_path": [method],
                })
                self.parse_all_fvs(blob, idx)
            pos = idx + 1

    def write_index(self):
        index = self.out_dir / "index.csv"
        fields = ["kind", "path", "size", "sha256", "fv_offset", "ffs_guid", "ffs_type", "ui", "section_path"]
        with index.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.rows)
        return index


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rom")
    parser.add_argument("out_dir")
    args = parser.parse_args()
    data = Path(args.rom).read_bytes()
    extractor = Extractor(args.out_dir)
    extractor.parse_all_fvs(data)
    extractor.scan_raw_lzma(data)
    index = extractor.write_index()
    print(f"wrote {len(extractor.rows)} images")
    print(index)


if __name__ == "__main__":
    main()
