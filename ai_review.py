#!/usr/bin/env python3
"""Review saved evidence. No target requests; outputs stay separate from source reports."""
import argparse
import sys
from recon81.ai_review import prepare_review, import_review


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('doctor', help='Check Codex setup; --probe sends a fixed evidence-free model request')
    p.add_argument('--probe', action='store_true'); p.add_argument('--output')
    p.add_argument('--timeout', type=int, default=60); p.add_argument('--model')
    p.add_argument('--first-response-timeout', type=int, default=60)
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
    p = sub.add_parser('batch-prepare')
    p.add_argument('--report', required=True); p.add_argument('--output', required=True)
    p.add_argument('--scope', action='append', required=True); p.add_argument('--authority')
    p.add_argument('--max-records', type=int, default=12); p.add_argument('--max-bytes', type=int, default=65536)
    p.add_argument('--body-bytes', type=int, default=6144)
    p = sub.add_parser('batch-import')
    p.add_argument('--batch', required=True); p.add_argument('--packet-id', required=True); p.add_argument('--result', required=True)
    p = sub.add_parser('batch-run')
    p.add_argument('--batch', required=True); p.add_argument('--timeout', type=int, default=300); p.add_argument('--model')
    p.add_argument('--first-response-timeout', type=int, default=180,
                   help='Seconds to wait for the first model response; bounded by --timeout (default: 180)')
    p.add_argument('--retry-failed', action='store_true'); p.add_argument('--max-attempts', type=int, default=3)
    p = sub.add_parser('batch-report')
    p.add_argument('--batch', required=True); p.add_argument('--output', required=True)
    p = sub.add_parser('coverage'); p.add_argument('--batch', required=True)
    p = sub.add_parser('evaluate'); p.add_argument('--review', required=True); p.add_argument('--labels', required=True); p.add_argument('--output', required=True)
    p = sub.add_parser('pdf'); p.add_argument('--review', required=True); p.add_argument('--output', required=True)
    p.add_argument('--font'); p.add_argument('--max-reviews', type=int, default=200)
    p = sub.add_parser('recommend', help='Offline multi-type candidate recommendations; --ai adds short, bounded model review')
    p.add_argument('--report', required=True); p.add_argument('--output', required=True)
    p.add_argument('--scope', action='append', required=True); p.add_argument('--authority')
    p.add_argument('--ai', action='store_true'); p.add_argument('--ai-limit', type=int, default=24)
    p.add_argument('--ai-include-surfaces', action='store_true', help='Include feature inspection surfaces in the existing AI budget')
    p.add_argument('--ai-batch-size', type=int, default=8); p.add_argument('--ai-workers', type=int, default=2)
    p.add_argument('--timeout', type=int, default=300); p.add_argument('--first-response-timeout', type=int, default=180)
    p.add_argument('--model')
    p.add_argument('--discover', action='store_true', help='Inspect bounded saved records outside rule signals; requires --ai')
    p.add_argument('--discovery-limit', type=int, default=4)
    cache = p.add_mutually_exclusive_group()
    cache.add_argument('--cache', help='Private AI reuse database; default is beside the output directory')
    cache.add_argument('--no-cache', action='store_true')
    p.add_argument('--cache-max-age', type=int, default=86400)
    p.add_argument('--feedback', help='Human candidate decisions bound to exact evidence')
    p = sub.add_parser('feedback', help='Append an explicit human follow-up decision to a separate private file')
    p.add_argument('--review', required=True); p.add_argument('--candidate-id', required=True)
    p.add_argument('--decision', required=True, choices=('follow_up', 'dismiss', 'needs_context'))
    p.add_argument('--note', required=True); p.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            import json
            from recon81.codex_review import diagnose
            from recon81.ai_review import _publish, _json
            result = diagnose(args.probe, args.timeout, args.model, args.first_response_timeout)
            if args.output:
                _publish(args.output, {'diagnostic.json': _json(result)})
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result['status'] == 'ready' else 2
        elif args.command == 'prepare':
            prepare_review(args.report, args.output, args.scope, args.max_records, args.max_bytes)
        elif args.command == 'import':
            import_review(args.packet, args.result, args.output)
        elif args.command == 'batch-prepare':
            from recon81.review_batch import prepare_batch
            from recon81.ai_review import load_json
            prepare_batch(args.report,args.output,args.scope,load_json(args.authority) if args.authority else None,
                          args.max_records,args.max_bytes,args.body_bytes)
        elif args.command == 'batch-import':
            from recon81.review_batch import import_packet
            import_packet(args.batch,args.packet_id,args.result)
        elif args.command in ('batch-run','coverage'):
            from recon81.review_batch import run_batch,refresh
            import json
            result = run_batch(args.batch,args.timeout,args.model,args.retry_failed,args.max_attempts,args.first_response_timeout) if args.command=='batch-run' else refresh(args.batch)
            print(json.dumps(result['summary'],ensure_ascii=False))
            return 3 if args.command=='batch-run' and result['summary']['completed_packets']!=result['summary']['packets'] else 0
        elif args.command == 'batch-report':
            from recon81.review_reporting import batch_report
            batch_report(args.batch,args.output)
        elif args.command == 'evaluate':
            from recon81.review_reporting import evaluate
            import json
            print(json.dumps(evaluate(args.review,args.labels,args.output)['metrics'],ensure_ascii=False))
        elif args.command == 'pdf':
            from recon81.review_reporting import export_pdf
            export_pdf(args.review,args.output,args.font,args.max_reviews)
        elif args.command == 'recommend':
            import json
            from pathlib import Path
            from recon81.candidate_report import create_recommendations
            from recon81.ai_review import load_json
            result = create_recommendations(args.report,args.output,args.scope,
                load_json(args.authority) if args.authority else None,args.ai,args.ai_limit,args.ai_batch_size,
                args.ai_workers,args.timeout,args.model,args.first_response_timeout,args.ai_include_surfaces,
                args.discover,args.discovery_limit,
                None if args.no_cache or not args.ai else args.cache or Path(args.output).parent/'candidate-ai-cache.sqlite3',
                args.cache_max_age,args.feedback)
            print(json.dumps(result['summary'],ensure_ascii=False))
            if result['summary']['ai_failed_packets']: return 3
        elif args.command == 'feedback':
            from recon81.candidate_feedback import save_feedback
            save_feedback(args.review,args.candidate_id,args.decision,args.note,args.output)
        else:
            from recon81.codex_review import run_review
            run_review(args.report, args.output, args.scope, args.max_records, args.max_bytes, args.timeout, args.model)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ImportError) as exc:
        # Never log raw captured evidence, subprocess output or credentials.
        from recon81.codex_review import ReviewFailure
        detail = exc.code+' ('+exc.stage+')' if isinstance(exc,ReviewFailure) else type(exc).__name__
        print('AI review failed: '+detail+'. See docs/V851.md troubleshooting.',file=sys.stderr)
        return 2
    print('Saved AI review output: ' + getattr(args,'output',getattr(args,'batch','')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
