"""Private subprocess entry point for static obfuscation."""
import base64
from dataclasses import asdict
import json
import sys


def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024,) * 2)
    except ImportError:
        pass  # Parent still enforces a wall-clock deadline on other platforms.
    from .obfuscate import MAX_INPUT, ObfuscationError, protect
    source = sys.stdin.buffer.read(MAX_INPUT + 1)
    try:
        result = asdict(protect(source))
        result['source'] = base64.b64encode(result['source']).decode('ascii')
    except ObfuscationError as exc:
        result = {'error': str(exc)}
    except MemoryError:
        result = {'error': 'The script exceeded the obfuscation memory limit. Try a smaller script.'}
    sys.stdout.write(json.dumps(result))


if __name__ == '__main__':
    main()
