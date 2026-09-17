import { redirect } from 'next/navigation';

/** The submission list and the scan list are one page now; this route only forwards. */
export default function SubmissionsRedirectPage(): never {
  redirect('/scans');
}
