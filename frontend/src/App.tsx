import React from 'react';
import { TraceExplorer } from './components/TraceExplorer.tsx';
import './App.css';

export const App: React.FC = () => {
  return (
    <div className="app-container">
      <TraceExplorer />
    </div>
  );
};

export default App;
