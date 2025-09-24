// History.jsx
import {useState, useEffect} from 'react';
import { supabase } from '../supabaseClient';

function getStoredUser() {
  try {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  } catch (error) {
    console.error('Error al obtener el usuario de localStorage:', error);
    return null;
  }
}

async function getUserFiles() {
  const user = getStoredUser();
  if (!user) {
    console.error('No hay usuario autenticado.');
    return null;
  }

  const { data: files, error } = await supabase
    .from('file')
    .select('*')
    .eq('user_id', user.id)
    .order('uploaded_at', { ascending: false }); // Ordena por fecha de creación descendente

  if (error) {
    console.error('Error al obtener los archivos:', error);
    return null;
  }

  return files;
}

const History = () => {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchFiles = async () => {
      setIsLoading(true);
      const userFiles = await getUserFiles();
      if (userFiles) {
        setHistory(userFiles);
      }
      setIsLoading(false);
    };

    fetchFiles();
  }, []); 
  return (
    <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm flex flex-col border border-gray-200 dark:border-slate-800 h-full overflow-hidden">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Historial de Archivos Escaneados
      </h2>
      
      {history.length === 0 ? (
        <div className="flex-grow flex items-center justify-center text-gray-400 dark:text-gray-500 text-center">
          <p>No hay archivos en el historial.</p>
        </div>
      ) : (
        <div className="overflow-x-auto h-full">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-800">
            <thead className="bg-gray-50 dark:bg-slate-900 sticky top-0">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Nombre del Archivo
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Estado
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Detecciones
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Fecha y Hora
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-950 divide-y divide-gray-200 dark:divide-slate-800">
              {history.map((item, index) => (
                <tr key={index} className="hover:bg-gray-50 dark:hover:bg-slate-900">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                    {item.name}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {item.isMalicious === true ? (
                      <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300">
                        Malicioso
                      </span>
                    ) : item.isMalicious === false ? (
                      <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                        Seguro
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                        Error
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                    {item.maliciousCount !== undefined ? `${item.maliciousCount} de ${item.totalAnalyzers}` : 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {item.date}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default History;