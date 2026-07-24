import { FileText } from 'lucide-react';

export default function Files() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Files</h1>
        <p className="text-gray-500 dark:text-gray-400">File system monitoring</p>
      </div>
      <div className="card">
        <div className="p-12 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/30">
            <FileText className="h-6 w-6 text-purple-600 dark:text-purple-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">File Activity</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            File collector coming in a future update. File create, modify, delete, and hash detection will appear here.
          </p>
        </div>
      </div>
    </div>
  );
}
