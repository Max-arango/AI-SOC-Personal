import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: Date | string, options?: Intl.DateTimeFormatOptions): string {
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...options,
  });
}

export function formatRelativeTime(date: Date | string): string {
  const d = new Date(date);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  
  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(d, { hour: undefined, minute: undefined });
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length - 3) + '...';
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    emergency: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
    alert: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
    critical: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
    error: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300',
    warning: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
    notice: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
    info: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300',
    debug: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
  };
  return colors[severity.toLowerCase()] || colors.info;
}

export function getRiskLevel(score: number): { label: string; color: string } {
  if (score >= 900) return { label: 'Critical', color: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300' };
  if (score >= 600) return { label: 'High', color: 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300' };
  if (score >= 300) return { label: 'Medium', color: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300' };
  if (score >= 100) return { label: 'Low', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' };
  return { label: 'Minimal', color: 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300' };
}