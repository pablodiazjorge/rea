import {
  ELECTRON_FUSE_SENTINEL,
  ELECTRON_FUSE_STATE_BYTES,
} from "../../../src/domain/electron/electronFuses.js";

export const FUSE_SENTINEL = Buffer.from(ELECTRON_FUSE_SENTINEL, "ascii");

/** Obsidian's observed version-1 states: disabled, enabled, then six more with the last enabled. */
export const OBSIDIAN_FUSE_BYTES = [
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.enabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.enabled,
] as const;

export const fuseWire = (version: number, fuses: readonly number[]): Buffer =>
  Buffer.from([version, fuses.length, ...fuses]);

export const thinMacho = (cpuType: number, body: Buffer): Buffer => {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(cpuType, 4);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(2, 12);
  return Buffer.concat([header, body]);
};

export const thinFuseImage = (
  fuses: readonly number[],
  version = 1,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => ({
  bytes: thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, fuseWire(version, fuses)]),
  ),
  sentinelOffset: 32,
});

export const universalFuseImage = (): {
  readonly bytes: Buffer;
  readonly left: {
    readonly fileOffset: number;
    readonly sentinelOffset: number;
  };
  readonly right: {
    readonly fileOffset: number;
    readonly sentinelOffset: number;
  };
} => {
  const left = thinMacho(
    0x01000007,
    Buffer.concat([FUSE_SENTINEL, fuseWire(1, OBSIDIAN_FUSE_BYTES)]),
  );
  const rightFuses = [...OBSIDIAN_FUSE_BYTES];
  rightFuses[3] = ELECTRON_FUSE_STATE_BYTES.enabled;
  const right = thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, fuseWire(1, rightFuses)]),
  );
  const tableEnd = 48;
  const table = Buffer.alloc(tableEnd);
  table.writeUInt32BE(0xcafebabe, 0);
  table.writeUInt32BE(2, 4);
  const writeEntry = (
    index: number,
    cpuType: number,
    offset: number,
    size: number,
  ) => {
    const base = 8 + index * 20;
    table.writeUInt32BE(cpuType, base);
    table.writeUInt32BE(0, base + 4);
    table.writeUInt32BE(offset, base + 8);
    table.writeUInt32BE(size, base + 12);
    table.writeUInt32BE(0, base + 16);
  };
  writeEntry(0, 0x01000007, tableEnd, left.length);
  writeEntry(1, 0x0100000c, tableEnd + left.length, right.length);
  return {
    bytes: Buffer.concat([table, left, right]),
    left: { fileOffset: tableEnd, sentinelOffset: tableEnd + 32 },
    right: {
      fileOffset: tableEnd + left.length,
      sentinelOffset: tableEnd + left.length + 32,
    },
  };
};

export const peFuseImage = (
  fuses: readonly number[],
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const header = Buffer.alloc(0x80);
  header.write("MZ", 0, "ascii");
  header.writeUInt32LE(0x80, 0x3c);
  const body = Buffer.concat([
    Buffer.from("PE\0\0", "binary"),
    FUSE_SENTINEL,
    fuseWire(1, fuses),
  ]);
  return { bytes: Buffer.concat([header, body]), sentinelOffset: 0x84 };
};

export const elfFuseImage = (
  fuses: readonly number[],
  version = 1,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => ({
  bytes: Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    FUSE_SENTINEL,
    fuseWire(version, fuses),
  ]),
  sentinelOffset: 4,
});

/** A PE image whose COFF header names `machine`, followed by a fuse wire. */
export const peMachineFuseImage = (
  machine: number,
  fuses: readonly number[],
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const header = Buffer.alloc(0x80);
  header.write("MZ", 0, "ascii");
  header.writeUInt32LE(0x80, 0x3c);
  const coff = Buffer.alloc(20);
  coff.writeUInt16LE(machine, 0);
  return {
    bytes: Buffer.concat([
      header,
      Buffer.from("PE\0\0", "binary"),
      coff,
      FUSE_SENTINEL,
      fuseWire(1, fuses),
    ]),
    sentinelOffset: 0x80 + 4 + coff.length,
  };
};

/** An ELF image with a valid fixed header naming `machine`, followed by a fuse wire. */
export const elfMachineFuseImage = (
  machine: number,
  fuses: readonly number[],
  {
    elfClass = 64,
    byteOrder = "little",
  }: {
    readonly elfClass?: 32 | 64;
    readonly byteOrder?: "little" | "big";
  } = {},
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const size = elfClass === 64 ? 64 : 52;
  const header = Buffer.alloc(size);
  header.set([0x7f, 0x45, 0x4c, 0x46, elfClass === 64 ? 2 : 1], 0);
  header[5] = byteOrder === "little" ? 1 : 2;
  header[6] = 1;
  const u16 = (value: number, offset: number) =>
    byteOrder === "little"
      ? header.writeUInt16LE(value, offset)
      : header.writeUInt16BE(value, offset);
  const u32 = (value: number, offset: number) =>
    byteOrder === "little"
      ? header.writeUInt32LE(value, offset)
      : header.writeUInt32BE(value, offset);
  u16(2, 16);
  u16(machine, 18);
  u32(1, 20);
  u16(size, elfClass === 64 ? 52 : 40);
  return {
    bytes: Buffer.concat([header, FUSE_SENTINEL, fuseWire(1, fuses)]),
    sentinelOffset: size,
  };
};

export const truncatedFuseImage = (): Buffer =>
  thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, Buffer.from([1, 4, 0x31])]),
  );

export const twoSentinelElf = (): {
  readonly bytes: Buffer;
  readonly offsets: readonly [number, number];
} => {
  const wire = fuseWire(1, OBSIDIAN_FUSE_BYTES);
  const first = 4;
  const second = first + FUSE_SENTINEL.length + wire.length + 2;
  return {
    bytes: Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      FUSE_SENTINEL,
      wire,
      Buffer.from([0, 0]),
      FUSE_SENTINEL,
      wire,
    ]),
    offsets: [first, second],
  };
};

export const sentinelFreeMacho = (): Buffer =>
  thinMacho(0x0100000c, Buffer.from("no fuse wire in this image"));
