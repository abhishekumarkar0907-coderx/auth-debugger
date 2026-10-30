/**
 * UI State helpers for failed vs genuine empty states.
 */

export const COPY = {
  ERROR_TITLE: 'We couldn’t load your traces.',
  ERROR_DETAIL:
    'The trace service may be unavailable. Check that the backend is running, then try again.',
  RETRY_BUTTON: 'Try again',
  EMPTY_TITLE: 'No traces yet',
  EMPTY_SUBTITLE: 'Once your app sends trace data, it’ll appear here.',
  SPANS_ERROR_TITLE: 'We couldn’t load your spans.',
} as const;

export type TraceListState = 'loading' | 'error' | 'empty' | 'filtered-empty' | 'list';

export function resolveTraceListState(params: {
  isLoading: boolean;
  hasError: boolean;
  hasLoaded: boolean;
  totalTraces: number;
  filteredTraces: number;
  filterQuery: string;
}): TraceListState {
  if (params.isLoading && params.totalTraces === 0) {
    return 'loading';
  }
  // When an error occurred, return 'error' (sidebar will avoid duplicate error text and suppress empty state)
  if (params.hasError) {
    return 'error';
  }
  // Keep empty state hidden until a successful response has arrived
  if (!params.hasLoaded) {
    return 'loading';
  }
  if (params.filteredTraces === 0) {
    if (params.totalTraces === 0) {
      return 'empty';
    }
    return 'filtered-empty';
  }
  return 'list';
}

export type WorkspaceMainState =
  | 'trace-error'
  | 'spans-error'
  | 'loading-spans'
  | 'empty-no-traces'
  | 'empty-trace-spans'
  | 'spans-view'
  | 'initial-loading';

export function resolveWorkspaceMainState(params: {
  traceError: string | null;
  spansError: string | null;
  isLoadingTraces: boolean;
  hasLoadedTraces: boolean;
  isLoadingSpans: boolean;
  spanCount: number;
  selectedTraceId: string | null;
}): WorkspaceMainState {
  // Trace list request failed -> show friendly error once in the main workspace
  if (params.traceError) {
    return 'trace-error';
  }
  // Preserve separate error state when a selected trace fails to load
  if (params.spansError) {
    return 'spans-error';
  }
  if (params.isLoadingSpans) {
    return 'loading-spans';
  }
  if (params.isLoadingTraces && !params.hasLoadedTraces) {
    return 'initial-loading';
  }
  // Keep empty state hidden until a successful response has confirmed there are no traces
  if (!params.hasLoadedTraces) {
    return 'initial-loading';
  }
  if (params.spanCount === 0) {
    if (params.selectedTraceId) {
      return 'empty-trace-spans';
    }
    // Genuine empty state after a successful response confirms no traces
    return 'empty-no-traces';
  }
  return 'spans-view';
}
