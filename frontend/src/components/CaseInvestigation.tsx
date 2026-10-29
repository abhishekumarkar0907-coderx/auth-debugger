import React, { useMemo, useState } from 'react';
import { DEMO_CASES, type CaseNode, type InvestigationCase } from '../mocks/demoData.ts';

export const CaseInvestigation: React.FC = () => {
  const [caseId, setCaseId] = useState(DEMO_CASES[0].id);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(DEMO_CASES[0].nodes[2].id);
  const [selectedRelationshipId, setSelectedRelationshipId] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Record<string, number>>({});
  const currentCase = DEMO_CASES.find((item) => item.id === caseId) || DEMO_CASES[0];
  const selectedNode = currentCase.nodes.find((node) => node.id === selectedNodeId) || null;
  const selectedRelationship = currentCase.relationships.find((item) => item.id === selectedRelationshipId) || null;
  const progress = completedSteps[currentCase.id] || 0;

  const setSelectedEntity = (nodeId: string) => {
    setSelectedNodeId(nodeId);
    setSelectedRelationshipId(null);
  };

  const chooseCase = (item: InvestigationCase) => {
    setCaseId(item.id);
    setSelectedNodeId(item.nodes.find((node) => node.suspicious)?.id || item.nodes[0]?.id || null);
    setSelectedRelationshipId(null);
  };

  const connectedRelationships = useMemo(
    () => selectedNode ? currentCase.relationships.filter((item) => item.from === selectedNode.id || item.to === selectedNode.id) : [],
    [currentCase, selectedNode],
  );

  return (
    <section className="case-workspace" aria-label="Sample case investigation">
      <aside className="case-list-panel">
        <div className="case-panel-heading">
          <span className="case-kicker">TRAINING DATA</span>
          <h2>Investigation cases</h2>
          <p>Choose a case to walk through its evidence.</p>
        </div>
        <div className="case-list">
          {DEMO_CASES.map((item) => (
            <button key={item.id} type="button" className={`case-list-card ${item.id === currentCase.id ? 'selected' : ''}`} onClick={() => chooseCase(item)}>
              <span className={`case-severity-dot severity-${item.severity.toLowerCase()}`} />
              <span className="case-card-copy">
                <span className="case-card-id">{item.id} <span>{item.status}</span></span>
                <strong>{item.title}</strong>
                <small>{item.updated}</small>
              </span>
            </button>
          ))}
        </div>
        <p className="demo-data-note">These scenarios are fictional sample data for the product walkthrough.</p>
      </aside>

      <div className="case-main-column">
        <header className="case-overview-card">
          <div className="case-overview-topline">
            <div>
              <span className="case-kicker">{currentCase.id} · AUTHORIZATION REVIEW</span>
              <h2>{currentCase.title}</h2>
            </div>
            <div className="case-overview-badges">
              <span className={`case-severity severity-${currentCase.severity.toLowerCase()}`}>{currentCase.severity} severity</span>
              <span className={`case-verdict ${currentCase.verdict === 'DETECTED' ? 'is-detected' : 'is-clear'}`}>{currentCase.verdict.replace('_', ' ')}</span>
            </div>
          </div>
          <p>{currentCase.summary}</p>
          <div className="case-summary-meta"><span>{currentCase.nodes.length} entities</span><i /> <span>{currentCase.relationships.length} observed relationships</span><i /> <span>Updated {currentCase.updated}</span></div>
        </header>

        <section className="network-card" aria-labelledby="network-title">
          <header className="network-card-heading">
            <div><span className="case-kicker">REQUEST PATH</span><h3 id="network-title">Entity relationships</h3></div>
            <div className="network-legend"><span><i className="legend-dot suspicious" />Flagged</span><span><i className="legend-dot" />Observed</span></div>
          </header>
          <div className="network-canvas">
            <svg className="case-network" viewBox="0 0 100 100" role="group" aria-label={`Interactive entity relationship graph for ${currentCase.id}`}>
              <defs><marker id="case-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0 L8 4 L0 8 z" /></marker></defs>
              {currentCase.relationships.map((edge) => {
                const from = currentCase.nodes.find((node) => node.id === edge.from)!;
                const to = currentCase.nodes.find((node) => node.id === edge.to)!;
                const active = edge.id === selectedRelationshipId;
                const suspicious = !!edge.suspicious;
                return <g key={edge.id} className={`network-edge ${suspicious ? 'suspicious' : ''} ${active ? 'active' : ''}`} role="button" tabIndex={0} aria-label={`${edge.label}: ${edge.evidence}`} onClick={() => { setSelectedRelationshipId(edge.id); setSelectedNodeId(null); }} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { setSelectedRelationshipId(edge.id); setSelectedNodeId(null); } }}>
                  <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} markerEnd="url(#case-arrow)" />
                  <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 2}>{edge.label}</text>
                </g>;
              })}
              {currentCase.nodes.map((node) => <NetworkNode key={node.id} node={node} selected={node.id === selectedNodeId} onSelect={() => setSelectedEntity(node.id)} />)}
            </svg>
          </div>
          <p className="network-hint">Select an entity or a connecting line to inspect its evidence.</p>
        </section>

        <section className="workflow-card" aria-labelledby="workflow-title">
          <div className="workflow-head"><div><span className="case-kicker">CASE WORKFLOW</span><h3 id="workflow-title">Investigation progress</h3></div><span className="workflow-progress-label">{progress} of {currentCase.workflow.length} complete</span></div>
          <div className="workflow-track"><span style={{ width: `${(progress / currentCase.workflow.length) * 100}%` }} /></div>
          <ol className="workflow-steps">
            {currentCase.workflow.map((step, index) => <li key={step} className={index < progress ? 'done' : index === progress ? 'current' : ''}><span className="workflow-step-number">{index < progress ? '✓' : `0${index + 1}`}</span><span>{step}</span></li>)}
          </ol>
          <button className="workflow-action" type="button" disabled={progress >= currentCase.workflow.length} onClick={() => setCompletedSteps((state) => ({ ...state, [currentCase.id]: Math.min(currentCase.workflow.length, progress + 1) }))}>{progress >= currentCase.workflow.length ? 'Walkthrough complete' : `Complete step ${progress + 1}`}</button>
        </section>
      </div>

      <aside className="case-evidence-panel">
        <section className="case-detail-section">
          <span className="case-kicker">SELECTED EVIDENCE</span>
          {selectedRelationship ? <>
            <h3>{selectedRelationship.label}</h3>
            <p className="case-evidence-description">{selectedRelationship.evidence}</p>
            <div className="relationship-route"><span>{currentCase.nodes.find((node) => node.id === selectedRelationship.from)?.label}</span><b>→</b><span>{currentCase.nodes.find((node) => node.id === selectedRelationship.to)?.label}</span></div>
            <span className={`evidence-flag ${selectedRelationship.suspicious ? 'flagged' : ''}`}>{selectedRelationship.suspicious ? 'Flagged relationship' : 'Observed relationship'}</span>
          </> : selectedNode ? <>
            <div className={`entity-avatar entity-${selectedNode.kind} ${selectedNode.suspicious ? 'flagged' : ''}`}>{selectedNode.label.slice(0, 1)}</div>
            <h3>{selectedNode.label}</h3>
            <span className="entity-role">{selectedNode.role}</span>
            <p className="case-evidence-description">{selectedNode.detail}</p>
            {selectedNode.suspicious && <span className="evidence-flag flagged">Suspicious activity linked</span>}
            {connectedRelationships.length > 0 && <div className="connected-evidence"><h4>Related evidence</h4>{connectedRelationships.map((item) => <button key={item.id} type="button" onClick={() => { setSelectedRelationshipId(item.id); setSelectedNodeId(null); }}><span className={item.suspicious ? 'evidence-link-dot flagged' : 'evidence-link-dot'} />{item.label}<span>→</span></button>)}</div>}
          </> : <p className="case-evidence-description">Select an entity or relationship in the graph to see its details.</p>}
        </section>

        <section className="case-detail-section finding-section">
          <span className="case-kicker">ANALYST SUMMARY</span>
          <h3>{currentCase.verdict === 'DETECTED' ? 'Authority gap identified' : 'No boundary violation found'}</h3>
          <p className="case-evidence-description">{currentCase.finding}</p>
          <div className="scope-comparison"><div><span>Required</span><strong>{currentCase.verdict === 'DETECTED' ? 'finance:export' : 'reports:read'}</strong></div><b>vs</b><div><span>Presented</span><strong>{currentCase.verdict === 'DETECTED' ? 'reports:read' : 'reports:read'}</strong></div></div>
          <p className="sample-disclaimer">Sample analysis for demonstration; not a live authorization decision.</p>
        </section>

        <section className="case-detail-section activity-section">
          <span className="case-kicker">TRACE TIMELINE</span>
          <h3>What happened</h3>
          <ol className="case-timeline">{currentCase.activity.map((item) => <li key={`${item.time}-${item.title}`}>
            <button type="button" className={`timeline-marker ${item.signal}`} aria-label={`Inspect ${item.title}`} onClick={() => setSelectedEntity(item.nodeId)} />
            <div><time>{item.time}</time><strong>{item.title}</strong><p>{item.description}</p></div>
          </li>)}</ol>
        </section>
      </aside>
    </section>
  );
};

const NetworkNode: React.FC<{ node: CaseNode; selected: boolean; onSelect: () => void }> = ({ node, selected, onSelect }) => (
  <g className={`network-node kind-${node.kind} ${node.suspicious ? 'suspicious' : ''} ${selected ? 'selected' : ''}`} role="button" tabIndex={0} aria-label={`${node.label}, ${node.role}${node.suspicious ? ', flagged' : ''}`} onClick={onSelect} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') onSelect(); }}>
    {node.suspicious && <circle className="node-halo" cx={node.x} cy={node.y} r="6.3" />}
    <circle className="node-circle" cx={node.x} cy={node.y} r="4.5" />
    <text className="node-label" x={node.x} y={node.y + 9}>{node.label}</text>
    <text className="node-role" x={node.x} y={node.y + 12.5}>{node.role}</text>
  </g>
);
