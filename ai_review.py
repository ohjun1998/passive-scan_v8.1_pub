#!/usr/bin/env python3
"""Review saved evidence. No target requests; outputs stay separate from source reports."""
import argparse
import sys
from recon81.ai_review import prepare_review, import_review


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'codex'):
        p = sub.add_parser(command)
        p.add_argument('--report', required=True)
        p.add_argument('--output', required=True)
        p.add_argument('--scope', action='append', required=True)
        p.add_argument('--max-records', type=int, default=100)
        p.add_argument('--max-bytes', type=int, default=500000)
        if command == 'codex':
            p.add_argument('--timeout', type=int, default=600)
            p.add_argument('--model')
    p = sub.add_parser('import')
    p.add_argument('--packet', required=True)
    p.add_argument('--result', required=True)
    p.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            prepare_review(args.report, args.output, args.scope, args.max_records, args.max_bytes)
        elif args.command == 'import':
            import_review(args.packet, args.result, args.output)
        else:
            from recon81.codex_review import run_review
            run_review(args.report, args.output, args.scope, args.max_records, args.max_bytes, args.timeout, args.model)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        # Never log raw captured evidence, subprocess output or credentials.
        print('AI review failed: ' + type(exc).__name__ + '. See docs/V84.md troubleshooting.', file=sys.stderr)
        return 2
    print('Saved AI review output: ' + args.output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
