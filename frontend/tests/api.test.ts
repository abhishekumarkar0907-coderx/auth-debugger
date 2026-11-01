import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_API_BASE_URL,
  FRIENDLY_ERROR_DETAIL,
  getInitialApiBaseUrl,
  buildApiUrl,
  ApiError,
  createDemoScenario,
  fetchHealth,
  fetchTraces,
  fetchTraceSpans,
  fetchRecentSpans,
  fetchTraceGraph,
  fetchTraceExplanation,
} from '../src/api.ts';

test('DEFAULT_API_BASE_URL defaults to empty string for same-origin relative requests', () => {
  assert.equal(DEFAULT_API_BASE_URL, '');
  assert.equal(getInitialApiBaseUrl(), '');
});

test('buildApiUrl generates same-origin relative routes by default', () => {
  assert.equal(buildApiUrl('/health'), '/health');
  assert.equal(buildApiUrl('/api/v1/traces'), '/api/v1/traces');
  assert.equal(buildApiUrl('/api/v1/traces/abc123'), '/api/v1/traces/abc123');
  assert.equal(buildApiUrl('/api/v1/spans?limit=50'), '/api/v1/spans?limit=50');
});

test('buildApiUrl formats custom base URLs cleanly, stripping trailing slashes', () => {
  assert.equal(buildApiUrl('/health', 'http://localhost:8000/'), 'http://localhost:8000/health');
  assert.equal(buildApiUrl('/api/v1/traces', 'http://localhost:8000'), 'http://localhost:8000/api/v1/traces');
});

test('ApiError preserves status, statusText, and details', () => {
  const err = new ApiError('Not found', 404, 'Not Found', { detail: 'Trace not found' });
  assert.equal(err.name, 'ApiError');
  assert.equal(err.status, 404);
  assert.equal(err.statusText, 'Not Found');
  assert.deepEqual(err.details, { detail: 'Trace not found' });
});

test('createDemoScenario posts to the selected backend fixture and validates its source', async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  let requestUrl = '';
  let requestMethod = '';
  let requestSignal: AbortSignal | null | undefined;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      requestUrl = String(input);
      requestMethod = init?.method || '';
      requestSignal = init?.signal;
      return new Response(JSON.stringify({
        scenario_id: 'normal-request',
        trace_id: 'demo-normal',
        span_count: 3,
        data_source: 'synthetic_demo',
      }), { status: 200 });
    };

    const response = await createDemoScenario(
      'normal-request',
      'http://localhost:8000/',
      controller.signal,
    );

    assert.equal(requestUrl, 'http://localhost:8000/api/v1/demo/scenarios/normal-request');
    assert.equal(requestMethod, 'POST');
    assert.equal(requestSignal, controller.signal);
    assert.equal(response.data_source, 'synthetic_demo');
    assert.equal(response.trace_id, 'demo-normal');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('createDemoScenario rejects malformed backend fixture metadata', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      scenario_id: 'normal-request',
      trace_id: 'demo-normal',
      span_count: 2,
      data_source: 'live',
    }), { status: 200 });

    await assert.rejects(
      createDemoScenario('normal-request'),
      { name: 'ApiError', status: 200, statusText: 'ContractError' },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchTraceSpans validates traceId requirement', async () => {
  await assert.rejects(
    async () => {
      await fetchTraceSpans('');
    },
    {
      message: 'trace_id is required',
    }
  );
});

test('fetchTraceGraph validates traceId requirement', async () => {
  await assert.rejects(
    async () => {
      await fetchTraceGraph('');
    },
    {
      message: 'trace_id is required',
    }
  );
});

test('fetchTraceGraph forwards cancellation and preserves abort errors', async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  let requestSignal: AbortSignal | null | undefined;
  try {
    globalThis.fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
      requestSignal = init?.signal;
      const error = new Error('Request aborted');
      error.name = 'AbortError';
      throw error;
    };

    await assert.rejects(
      fetchTraceGraph('trace-1', undefined, controller.signal),
      { name: 'AbortError' },
    );

    assert.equal(requestSignal, controller.signal);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchTraceExplanation targets the current finding and forwards cancellation', async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  let requestUrl = '';
  let requestSignal: AbortSignal | null | undefined;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      requestUrl = String(input);
      requestSignal = init?.signal;
      return new Response(JSON.stringify({
        status: 'unavailable',
        finding_id: 'finding?1',
        explanation: null,
        message: 'Provider is not configured',
      }), { status: 200 });
    };

    const response = await fetchTraceExplanation(
      'trace/1',
      'finding?1',
      controller.signal,
    );

    assert.equal(
      requestUrl,
      '/api/v1/traces/trace%2F1/explanation?finding_id=finding%3F1',
    );
    assert.equal(requestSignal, controller.signal);
    assert.equal(response.status, 'unavailable');
    assert.equal(response.finding_id, 'finding?1');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchTraceExplanation rejects a mismatched finding response', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      status: 'ready',
      finding_id: 'another-finding',
      explanation: null,
    }), { status: 200 });

    await assert.rejects(
      fetchTraceExplanation('trace-1', 'finding-1'),
      { name: 'ApiError', status: 200, statusText: 'ContractError' },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetch functions use same-origin relative paths by default for Vite proxying', async () => {
  const originalFetch = globalThis.fetch;
  const calls: { url: string; method: string }[] = [];

  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: init?.method || 'GET' });

      if (url === '/health') {
        return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
      }
      if (url === '/api/v1/traces') {
        return new Response(
          JSON.stringify([
            { trace_id: '001122', span_count: 2, services: ['frontend', 'auth'] },
          ]),
          { status: 200 }
        );
      }
      if (url === '/api/v1/traces/001122') {
        return new Response(
          JSON.stringify([
            {
              trace_id: '001122',
              span_id: 's1',
              parent_span_id: null,
              service_name: 'frontend',
              span_name: 'GET /login',
              start_time_unix_nano: 1000,
              end_time_unix_nano: 2000,
              duration_ms: 1.0,
              span_kind: 2,
              status_code: 1,
              attributes: {},
            },
          ]),
          { status: 200 }
        );
      }
      if (url === '/api/v1/spans?limit=50') {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (url === '/api/v1/traces/001122/graph') {
        return new Response(
          JSON.stringify({
            trace_id: '001122',
            nodes: [{ id: 'service-1', type: 'service', label: 'api', metadata: {} }],
            edges: [],
            authority_amplification_hops: [],
            security_analysis: null,
          }),
          { status: 200 }
        );
      }

      return new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 });
    };

    // Test health - default relative path
    const health = await fetchHealth();
    assert.deepEqual(health, { status: 'ok' });
    assert.equal(calls[0].url, '/health');

    // Test trace list - default relative path
    const traces = await fetchTraces();
    assert.equal(traces.length, 1);
    assert.equal(traces[0].trace_id, '001122');
    assert.equal(calls[1].url, '/api/v1/traces');

    // Test trace spans - default relative path
    const spans = await fetchTraceSpans('001122');
    assert.equal(spans.length, 1);
    assert.equal(spans[0].span_name, 'GET /login');
    assert.equal(calls[2].url, '/api/v1/traces/001122');

    // Test recent spans - default relative path
    const recent = await fetchRecentSpans(50);
    assert.deepEqual(recent, []);
    assert.equal(calls[3].url, '/api/v1/spans?limit=50');

    // Test trace graph - default relative path
    const graph = await fetchTraceGraph('001122');
    assert.equal(graph.trace_id, '001122');
    assert.equal(graph.nodes[0].label, 'api');
    assert.equal(calls[4].url, '/api/v1/traces/001122/graph');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetchTraceGraph rejects malformed successful responses', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      trace_id: '001122',
      nodes: [{ id: 'node-a', type: 'service', label: 'api', metadata: {} }],
      edges: [{ source: 'node-a', target: 'missing', type: 'calls', trace_id: '001122', metadata: {} }],
      authority_amplification_hops: [],
      security_analysis: null,
    }), { status: 200 });

    await assert.rejects(
      fetchTraceGraph('001122'),
      { name: 'ApiError', status: 200, statusText: 'ContractError' },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('malformed trace and span arrays are surfaced as contract errors', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL) => {
      const url = String(input);
      return new Response(JSON.stringify(url === '/api/v1/traces'
        ? [{ trace_id: 'trace-a', span_count: 'many', services: [] }]
        : [{ trace_id: 'trace-a', span_id: 'span-a' }]), { status: 200 });
    };

    await assert.rejects(fetchTraces(), { name: 'ApiError', statusText: 'ContractError' });
    await assert.rejects(fetchTraceSpans('trace-a'), { name: 'ApiError', statusText: 'ContractError' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('missing graph route is distinguished from a missing trace', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: 'Not Found' }), { status: 404 });
    await assert.rejects(
      fetchTraceGraph('trace-a'),
      { message: 'The backend does not expose GET /api/v1/traces/{trace_id}/graph.' },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fetch functions respect explicit custom baseUrl when provided', async () => {
  const originalFetch = globalThis.fetch;
  const calls: { url: string; method: string }[] = [];

  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: init?.method || 'GET' });

      if (url === 'http://custom-proxy:9000/health') {
        return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
      }
      return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
    };

    await fetchHealth('http://custom-proxy:9000');
    assert.equal(calls[0].url, 'http://custom-proxy:9000/health');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('response error handling reads body only once and provides friendly message on non-JSON error', async () => {
  const originalFetch = globalThis.fetch;
  let textReadCount = 0;

  try {
    globalThis.fetch = async () => {
      const resp = new Response('<html>502 Bad Gateway</html>', {
        status: 502,
        statusText: 'Bad Gateway',
        headers: { 'content-type': 'text/html' },
      });

      // Spy on text()
      const originalText = resp.text.bind(resp);
      resp.text = async () => {
        textReadCount++;
        return originalText();
      };
      return resp;
    };

    await assert.rejects(
      async () => {
        await fetchTraces();
      },
      (err: unknown) => {
        assert(err instanceof ApiError);
        assert.equal(err.status, 502);
        assert.equal(err.statusText, 'Bad Gateway');
        // Must show friendly copy, NOT raw syntax/stream error
        assert.equal(err.message, FRIENDLY_ERROR_DETAIL);
        assert.doesNotMatch(err.message, /body stream already read/i);
        // Details contain underlying raw response for debugging
        assert.equal(err.details, '<html>502 Bad Gateway</html>');
        return true;
      }
    );

    // Body was read exactly once
    assert.equal(textReadCount, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('network connection errors map to friendly error copy without leaking raw JS errors', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = async () => {
      throw new TypeError('Failed to fetch');
    };

    await assert.rejects(
      async () => {
        await fetchTraces();
      },
      (err: unknown) => {
        assert(err instanceof ApiError);
        assert.equal(err.status, 0);
        assert.equal(err.statusText, 'NetworkError');
        assert.equal(err.message, FRIENDLY_ERROR_DETAIL);
        assert.doesNotMatch(err.message, /TypeError/i);
        assert.equal(err.details, 'Failed to fetch');
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('200 responses with non-JSON content map to friendly error copy and log details', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = async () => {
      return new Response('Not valid JSON', { status: 200 });
    };

    await assert.rejects(
      async () => {
        await fetchTraces();
      },
      (err: unknown) => {
        assert(err instanceof ApiError);
        assert.equal(err.status, 200);
        assert.equal(err.statusText, 'ParseError');
        assert.equal(err.message, FRIENDLY_ERROR_DETAIL);
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
