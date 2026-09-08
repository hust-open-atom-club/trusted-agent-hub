'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTranslation } from 'react-i18next';
import { useAuth } from '@/lib/auth';

export default function AccountPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { user, loading, updateProfile, changePassword } = useAuth();

  const [displayName, setDisplayName] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [profileError, setProfileError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [profileMessage, setProfileMessage] = useState('');
  const [passwordMessage, setPasswordMessage] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    if (loading) return;
    if (!user) {
      router.replace('/login?redirect=/account');
      return;
    }
    setDisplayName(user.display_name);
  }, [loading, router, user]);

  const handleProfileSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setProfileError('');
    setProfileMessage('');

    const nextDisplayName = displayName.trim();
    if (!nextDisplayName) {
      setProfileError(t('account.display_name_required'));
      return;
    }

    setSavingProfile(true);
    try {
      const saved = await updateProfile(nextDisplayName);
      if (!saved) return;
      setDisplayName(nextDisplayName);
      setProfileMessage(t('account.profile_saved'));
    } catch (error: unknown) {
      setProfileError(error instanceof Error ? error.message : t('account.auth_required'));
    } finally {
      setSavingProfile(false);
    }
  };

  const handlePasswordSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setPasswordError('');
    setPasswordMessage('');

    if (!currentPassword) {
      setPasswordError(t('account.current_password_required'));
      return;
    }
    if (newPassword.length < 6) {
      setPasswordError(t('account.password_too_short'));
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError(t('account.password_mismatch'));
      return;
    }

    setChangingPassword(true);
    try {
      const changed = await changePassword(currentPassword, newPassword);
      if (!changed) return;
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordMessage(t('account.password_changed'));
    } catch (error: unknown) {
      setPasswordError(error instanceof Error ? error.message : t('account.auth_required'));
    } finally {
      setChangingPassword(false);
    }
  };

  if (loading || !user) {
    return (
      <div className="account-page">
        <div className="account-card">
          <div className="empty-state">
            <h3>{t('home.loading')}</h3>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="account-page">
      <div className="account-card">
        <div className="account-header">
          <h1>{t('account.title')}</h1>
          <p>{t('account.subtitle')}</p>
        </div>

        <section className="account-section">
          <h2>{t('account.profile_title')}</h2>
          {profileError && <div className="account-message account-message-error">{profileError}</div>}
          {profileMessage && <div className="account-message account-message-success">{profileMessage}</div>}
          <form className="login-form" onSubmit={handleProfileSubmit}>
            <div className="form-field">
              <label htmlFor="account-email">{t('account.email')}</label>
              <input id="account-email" type="email" value={user.email} readOnly />
              <span className="account-help">{t('account.email_readonly')}</span>
            </div>

            <div className="form-field">
              <label htmlFor="account-display-name">{t('account.display_name')}</label>
              <input
                id="account-display-name"
                type="text"
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
                placeholder={t('account.display_name_placeholder')}
                maxLength={64}
                autoComplete="name"
                disabled={savingProfile}
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={savingProfile}>
              {savingProfile ? t('account.saving_profile') : t('account.save_profile')}
            </button>
          </form>
        </section>

        <section className="account-section">
          <h2>{t('account.password_title')}</h2>
          {passwordError && <div className="account-message account-message-error">{passwordError}</div>}
          {passwordMessage && <div className="account-message account-message-success">{passwordMessage}</div>}
          <form className="login-form" onSubmit={handlePasswordSubmit}>
            <div className="form-field">
              <label htmlFor="current-password">{t('account.current_password')}</label>
              <input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                autoComplete="current-password"
                disabled={changingPassword}
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="new-password">{t('account.new_password')}</label>
              <input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder={t('account.password_placeholder')}
                autoComplete="new-password"
                disabled={changingPassword}
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="confirm-new-password">{t('account.confirm_password')}</label>
              <input
                id="confirm-new-password"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                autoComplete="new-password"
                disabled={changingPassword}
                required
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={changingPassword}>
              {changingPassword ? t('account.changing_password') : t('account.change_password')}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
