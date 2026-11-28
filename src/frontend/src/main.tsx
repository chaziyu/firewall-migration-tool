import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import './features/chat/ConfigChatWidget.css'
import './features/report/SecurityAuditPanel.css'
import './features/report/PmLookupPanel.css'
import './features/report/simulatorsAndDiff.css'
import './features/report/SslToIpsecPanel.css'
import './features/tsf/TsfExplorer.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
