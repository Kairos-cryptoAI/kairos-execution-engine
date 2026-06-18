from kairos_execution.ratelimit import TokenBucket


def test_bucket_allows_capacity_then_blocks():
    b = TokenBucket(capacity=3, refill_period_s=60)
    assert sum(b.try_acquire() for _ in range(3)) == 3
    assert b.try_acquire() is False
