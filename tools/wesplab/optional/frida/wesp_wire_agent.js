'use strict';

const MAX_REGION = 1024 * 1024;
let schemas = {};
let sequence = 0;
let lastPort = null;

function bytesHex(buffer) {
  if (buffer === null) return '';
  return Array.from(new Uint8Array(buffer)).map(x => x.toString(16).padStart(2, '0')).join('');
}

function safeRead(pointer, size) {
  if (size < 0 || size > MAX_REGION || pointer.isNull()) return null;
  try { return pointer.readByteArray(size); } catch (_) { return null; }
}

const sendAddress = Module.findGlobalExportByName ?
  Module.findGlobalExportByName('FilterSendMessage') :
  Module.findExportByName(null, 'FilterSendMessage');
if (sendAddress === null) throw new Error('FilterSendMessage export not found');

Interceptor.attach(sendAddress, {
  onEnter(args) {
    this.started = Date.now();
    this.port = args[0].toString();
    lastPort = args[0];
    this.input = args[1];
    this.inputSize = args[2].toUInt32();
    this.outputSize = args[4].toUInt32();
    this.envelope = safeRead(this.input, Math.min(this.inputSize, 0x40));
    this.requestId = this.envelope && this.inputSize >= 4 ? this.input.readU32() : null;
    this.regions = [];
    this.relocations = [];
    const definitions = schemas[String(this.requestId)] || [];
    for (const item of definitions) {
      try {
        const slot = this.input.add(item.envelope_offset);
        const target = slot.readPointer();
        const size = item.fixed_size !== undefined ? item.fixed_size :
          this.input.add(item.size_offset).readU32();
        const data = safeRead(target, size);
        this.regions.push({name: item.name, original_pointer: target.toString(), size,
          data_hex: bytesHex(data), captured: data !== null});
        this.relocations.push({envelope_offset: item.envelope_offset, region: item.name});
      } catch (error) {
        this.regions.push({name: item.name, captured: false, error: String(error)});
      }
    }
  },
  onLeave(result) {
    send({schema: 'wesplab.wire-capture.v1', abi: '0.1.0.156346177+c3490e8c', sequence: ++sequence,
      timestamp_utc: new Date().toISOString(), port_handle: this.port,
      request_id: this.requestId, input_size: this.inputSize,
      output_size: this.outputSize, envelope_hex: bytesHex(this.envelope),
      regions: this.regions, relocations: this.relocations, result_hresult: result.toInt32(),
      elapsed_ms: Date.now() - this.started});
  }
});

function hexBytes(text) {
  if (typeof text !== 'string' || text.length % 2 !== 0) throw new Error('malformed hex');
  const result = [];
  for (let i = 0; i < text.length; i += 2) result.push(parseInt(text.slice(i, i + 2), 16));
  return result;
}

rpc.exports = {
  replay(record, allowMutating) {
    if (lastPort === null) throw new Error('no live FilterSendMessage port observed in this process');
    const safeIds = new Set([0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0f, 0x10, 0x15, 0x16, 0x18]);
    const envelopeBytes = hexBytes(record.envelope_hex || '');
    if (envelopeBytes.length !== 0x40) throw new Error('envelope must be exactly 0x40 bytes');
    const requestId = envelopeBytes[0] | (envelopeBytes[1] << 8) |
      (envelopeBytes[2] << 16) | (envelopeBytes[3] << 24);
    if (!safeIds.has(requestId) && !allowMutating) throw new Error('mutating request refused');
    const envelope = Memory.alloc(0x40);
    envelope.writeByteArray(envelopeBytes);
    const allocations = {};
    for (const region of (record.regions || [])) {
      const bytes = hexBytes(region.data_hex || '');
      if (bytes.length > MAX_REGION) throw new Error('region exceeds safety limit');
      const allocation = Memory.alloc(Math.max(bytes.length, 1));
      if (bytes.length) allocation.writeByteArray(bytes);
      allocations[region.name] = allocation;
    }
    for (const relocation of (record.relocations || [])) {
      if (!(relocation.region in allocations)) throw new Error('unknown relocation region');
      const offset = Number(relocation.envelope_offset);
      if (offset < 0 || offset + Process.pointerSize > 0x40 || offset % Process.pointerSize !== 0)
        throw new Error('invalid relocation offset');
      envelope.add(offset).writePointer(allocations[relocation.region]);
    }
    const outputSize = Math.min(Number(record.output_size || 65536), MAX_REGION);
    const output = Memory.alloc(Math.max(outputSize, 1));
    const returned = Memory.alloc(4); returned.writeU32(0);
    const call = new NativeFunction(sendAddress, 'int', ['pointer', 'pointer', 'uint', 'pointer', 'uint', 'pointer']);
    const hr = call(lastPort, envelope, 0x40, output, outputSize, returned);
    const used = Math.min(returned.readU32(), outputSize);
    return {schema: 'wesplab.wire-replay-result.v1', request_id: requestId,
      hresult: hr, bytes_returned: returned.readU32(), output_hex: bytesHex(safeRead(output, used))};
  }
};

recv('configure', message => { schemas = message.payload.schemas || {}; }).wait();
