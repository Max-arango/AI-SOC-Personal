import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Bot, Send, AlertTriangle } from 'lucide-react';
import * as api from '../utils/tauriApi';

const SUGGESTED_PROMPTS = [
  'Summarize recent security activity on this system',
  'Explain the top risks detected in the last 24 hours',
  'What should I investigate in the process tree?',
  'Are there any signs of lateral movement?',
  'Check for persistence mechanisms on this host',
];

function renderMarkdown(text: string): string {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-200 dark:bg-gray-600 px-1 rounded text-xs">$1</code>')
    .replace(/\n/g, '<br/>');
}

export default function AiAssistant() {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<{ role: string; content: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [convId, setConvId] = useState<string | undefined>();

  const alerts = useQuery({
    queryKey: ['alerts-ai-ctx'],
    queryFn: () => api.getAlerts({ limit: 5 }),
    refetchInterval: 30000,
  });

  const handleSend = async (msg?: string) => {
    const text = (msg || input).trim();
    if (!text) return;
    if (!msg) setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: text }]);
    setLoading(true);
    try {
      const resp = await api.chatAi(text, convId);
      setConvId(resp.conversation_id);
      setMessages((prev) => [...prev, { role: 'assistant', content: resp.response }]);
    } catch (e: any) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `Error: ${String(e)}` }]);
    }
    setLoading(false);
  };

  const activeAlerts = alerts.data?.alerts?.filter(
    (a) => a.state === 'new' || a.state === 'acknowledged',
  ) ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Assistant</h1>
        <p className="text-gray-500 dark:text-gray-400">Ask Sentinel AI about your security posture</p>
      </div>

      {activeAlerts.length > 0 && (
        <div className="card p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <span className="text-sm font-medium text-amber-800 dark:text-amber-200">
              {activeAlerts.length} active alerts — you can ask me about them
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {activeAlerts.slice(0, 3).map((a) => (
              <button
                key={a.id}
                onClick={() => handleSend(`Explain alert: ${a.rule_id.replace(/_/g, ' ')}`)}
                className="text-xs bg-white dark:bg-gray-800 border border-amber-300 dark:border-amber-700 rounded px-2 py-1 hover:bg-amber-100 dark:hover:bg-amber-900/40"
              >
                {a.rule_id.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="card flex flex-col h-[55vh]">
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.length === 0 ? (
            <div className="flex h-full items-center justify-center flex-col">
              <div className="text-center mb-6">
                <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-purple-100 dark:bg-purple-900/30">
                  <Bot className="h-8 w-8 text-purple-600 dark:text-purple-400" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Sentinel AI Assistant</h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  Ask questions about threats, alerts, or your security posture.
                </p>
              </div>
              <div className="flex flex-wrap gap-2 justify-center max-w-md">
                {SUGGESTED_PROMPTS.map((prompt) => (
                  <button
                    key={prompt}
                    onClick={() => handleSend(prompt)}
                    className="text-xs bg-gray-100 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-full px-3 py-1.5 hover:bg-purple-50 dark:hover:bg-purple-900/20 text-gray-600 dark:text-gray-300"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] rounded-lg px-4 py-2 ${
                  m.role === 'user'
                    ? 'bg-primary-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white'
                }`}>
                  <div
                    className="text-sm whitespace-pre-wrap"
                    dangerouslySetInnerHTML={{ __html: renderMarkdown(m.content) }}
                  />
                </div>
              </div>
            ))
          )}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2">
                <p className="text-sm text-gray-500">Thinking...</p>
              </div>
            </div>
          )}
        </div>
        <div className="border-t border-gray-200 dark:border-gray-700 p-4">
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask about threats, alerts, or security..."
              className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-4 py-2 text-sm text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
            <button
              onClick={() => handleSend()}
              disabled={loading || !input.trim()}
              className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary-600 text-white hover:bg-primary-700 disabled:opacity-50"
            >
              <Send className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
