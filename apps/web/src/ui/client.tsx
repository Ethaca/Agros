import { hydrateRoot } from 'react-dom/client';
import { App, type PageName, type PageProps } from './app.tsx';

const data = document.getElementById('page-data');
const root = document.getElementById('root');
if (data && root) {
  const { name, props } = JSON.parse(data.textContent ?? '{}') as { name: PageName; props: PageProps<PageName> };
  hydrateRoot(root, <App name={name} props={props} />);
}
