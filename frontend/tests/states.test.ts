import test from 'node:test';
import assert from 'node:assert/strict';
import {
  COPY,
  resolveTraceListState,
  resolveWorkspaceMainState,
} from '../src/utils/stateHelpers.ts';

test('COPY contains exact friendly wording required by specifications', () => {
  assert.equal(COPY.ERROR_TITLE, 'We couldn’t load your traces.');
  assert.equal(
    COPY.ERROR_DETAIL,
    'The trace service may be unavailable. Check that the backend is running, then try again.'
  );
  assert.equal(COPY.RETRY_BUTTON, 'Try again');
  assert.equal(COPY.EMPTY_TITLE, 'No traces yet');
  assert.equal(COPY.EMPTY_SUBTITLE, 'Once your app sends trace data, it’ll appear here.');
  assert.equal(COPY.SPANS_ERROR_TITLE, 'We couldn’t load your spans.');
});

test('resolveTraceListState: error state suppresses empty state without duplicate error', () => {
  const stateOnError = resolveTraceListState({
    isLoading: false,
    hasError: true,
    hasLoaded: false,
    totalTraces: 0,
    filteredTraces: 0,
    filterQuery: '',
  });
  // Must return 'error', which hides empty state and allows single error display in workspace
  assert.equal(stateOnError, 'error');
  assert.notEqual(stateOnError, 'empty');
});

test('resolveTraceListState: empty state is kept hidden until a successful response arrives', () => {
  // Before any response has arrived (hasLoaded: false), empty state MUST NOT show
  const stateBeforeLoad = resolveTraceListState({
    isLoading: false,
    hasError: false,
    hasLoaded: false,
    totalTraces: 0,
    filteredTraces: 0,
    filterQuery: '',
  });
  assert.notEqual(stateBeforeLoad, 'empty');
  assert.equal(stateBeforeLoad, 'loading');

  // After a successful response (hasLoaded: true) confirming 0 traces, genuine empty state is shown
  const stateAfterLoad = resolveTraceListState({
    isLoading: false,
    hasError: false,
    hasLoaded: true,
    totalTraces: 0,
    filteredTraces: 0,
    filterQuery: '',
  });
  assert.equal(stateAfterLoad, 'empty');
});

test('resolveTraceListState: filtered empty state is returned when query matches 0 traces', () => {
  const stateFiltered = resolveTraceListState({
    isLoading: false,
    hasError: false,
    hasLoaded: true,
    totalTraces: 5,
    filteredTraces: 0,
    filterQuery: 'nonexistent-service',
  });
  assert.equal(stateFiltered, 'filtered-empty');
});

test('resolveWorkspaceMainState: traceError returns trace-error once and suppresses empty state', () => {
  const workspaceState = resolveWorkspaceMainState({
    traceError: 'The trace service may be unavailable. Check that the backend is running, then try again.',
    spansError: null,
    isLoadingTraces: false,
    hasLoadedTraces: false,
    isLoadingSpans: false,
    spanCount: 0,
    selectedTraceId: null,
  });
  assert.equal(workspaceState, 'trace-error');
  assert.notEqual(workspaceState, 'empty-no-traces');
});

test('resolveWorkspaceMainState: preserves separate error state for selected trace failing to load', () => {
  // Trace list succeeded (hasLoadedTraces: true, traceError: null), but spans for selected trace failed
  const workspaceState = resolveWorkspaceMainState({
    traceError: null,
    spansError: 'The trace service may be unavailable. Check that the backend is running, then try again.',
    isLoadingTraces: false,
    hasLoadedTraces: true,
    isLoadingSpans: false,
    spanCount: 0,
    selectedTraceId: '00112233445566778899aabbccddeeff',
  });
  // Must return 'spans-error', preserving the separate error state for selected trace
  assert.equal(workspaceState, 'spans-error');
  assert.notEqual(workspaceState, 'trace-error');
  assert.notEqual(workspaceState, 'empty-no-traces');
});

test('resolveWorkspaceMainState: empty state is kept hidden until a successful response confirms no traces', () => {
  // Initial state before response has arrived
  const stateBeforeLoad = resolveWorkspaceMainState({
    traceError: null,
    spansError: null,
    isLoadingTraces: true,
    hasLoadedTraces: false,
    isLoadingSpans: false,
    spanCount: 0,
    selectedTraceId: null,
  });
  assert.equal(stateBeforeLoad, 'initial-loading');
  assert.notEqual(stateBeforeLoad, 'empty-no-traces');

  // After a successful response confirming 0 traces
  const stateAfterLoad = resolveWorkspaceMainState({
    traceError: null,
    spansError: null,
    isLoadingTraces: false,
    hasLoadedTraces: true,
    isLoadingSpans: false,
    spanCount: 0,
    selectedTraceId: null,
  });
  assert.equal(stateAfterLoad, 'empty-no-traces');
});
