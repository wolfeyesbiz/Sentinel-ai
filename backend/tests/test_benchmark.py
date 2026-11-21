import asyncio
import time
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload

async def run_throughput_benchmark(total_requests: int = 5000):
    print(f"\n--- RUNNING SENTINEL AI HIGH-THROUGHPUT PERFORMANCE BENCHMARK ---")
    print(f"Benchmarking {total_requests} concurrent requests through WAF Threat Engine...")
    
    payload = RequestInspectionPayload(
        method="GET",
        path="/api/products",
        query_params={"category": "electronics", "limit": "20"},
        client_ip="10.0.0.50",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )

    start_time = time.perf_counter()
    
    # Process in parallel batches of 500
    batch_size = 500
    completed = 0
    
    for i in range(0, total_requests, batch_size):
        tasks = [threat_engine.inspect_request(payload) for _ in range(batch_size)]
        await asyncio.gather(*tasks)
        completed += batch_size

    total_time = time.perf_counter() - start_time
    req_per_sec = completed / max(0.001, total_time)
    avg_latency_ms = (total_time / completed) * 1000

    print(f"Completed: {completed} requests in {total_time:.3f} seconds")
    print(f"Throughput: {req_per_sec:.0f} req/sec")
    print(f"Average Inspection Latency: {avg_latency_ms:.3f} ms")
    assert avg_latency_ms < 10.0, f"Average latency {avg_latency_ms}ms exceeded 10ms threshold"
    print("✅ HIGH THROUGHPUT BENCHMARK PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_throughput_benchmark(3000))
