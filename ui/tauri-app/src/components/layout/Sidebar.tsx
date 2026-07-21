import { NavLink, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  Globe, 
  FileText, 
  Shield, 
  Bot, 
  Settings,
  ChevronRight
} from 'lucide-react';
import { clsx } from 'clsx';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Events', href: '/events', icon: Activity },
  { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'Processes', href: '/processes', icon: Cpu },
  { name: 'Network', href: '/network', icon: Globe },
  { name: 'Files', href: '/files', icon: FileText },
  { name: 'Risk', href: '/risk', icon: Shield },
  { name: 'AI Assistant', href: '/ai-chat', icon: Bot },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const location = useLocation();
  
  return (
    <aside className="fixed top-0 left-0 z-40 h-screen w-64 transform bg-white border-r border-gray-200 transition-transform duration-200 ease-in-out lg:translate-x-0 dark:bg-gray-900 dark:border-gray-700">
      <div className="flex h-full flex-col">
        {/* Logo */}
        <div className="flex h-16 items-center px-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-lg font-semibold text-gray-900 dark:text-white">Sentinel AI</span>
          </div>
        </div>
        
        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-4 overflow-y-auto" aria-label="Main navigation">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            const Icon = item.icon;
            
            return (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) => clsx(
                  'sidebar-item group',
                  isActive && 'sidebar-item-active'
                )}
                aria-current={isActive ? 'page' : undefined}
              >
                <Icon className="h-5 w-5 shrink-0 transition-colors group-hover:text-primary-600 dark:group-hover:text-primary-400" 
                      aria-hidden="true" />
                <span className="truncate">{item.name}</span>
                {isActive && (
                  <ChevronRight className="ml-auto h-4 w-4 text-primary-600 dark:text-primary-400" aria-hidden="true" />
                )}
              </NavLink>
            );
          })}
        </nav>
        
        {/* Footer */}
        <div className="border-t border-gray-200 p-4 dark:border-gray-700">
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Sentinel AI v0.1.0
          </div>
        </div>
      </div>
    </aside>
  );
}