using System;
using LibGit2Sharp.Core;
using LibGit2Sharp.Handlers;
#if __IOS__
using ObjCRuntime;
#endif

namespace LibGit2Sharp
{
    /// <summary>
    /// Class to translate libgit2 callbacks into delegates exposed by LibGit2Sharp.
    /// Handles generating libgit2 git_remote_callbacks datastructure given a set
    /// of LibGit2Sharp delegates and handles propagating libgit2 callbacks into
    /// corresponding LibGit2Sharp exposed delegates.
    /// </summary>
    internal class RemoteCallbacks
    {

#pragma warning disable CA1416

        #region Static Fetch Callbacks
        static RemoteCallbacks CurrentFetchCallback;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.remote_progress_callback))]
#endif
        internal static int StaticFetchProgressHandler(IntPtr str, int len, IntPtr data)
            => CurrentFetchCallback?.GitProgressHandler(str, len, data) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_transfer_progress_callback))]
#endif
        internal static int StaticFetchDownloadTransferProgressHandler(ref GitTransferProgress progress, IntPtr payload)
            => CurrentFetchCallback?.GitDownloadTransferProgressHandler(ref progress, payload) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.remote_update_tips_callback))]
#endif
        internal static int StaticFetchUpdateTipsHandler(IntPtr str, ref GitOid oldId, ref GitOid newId, IntPtr data)
            => CurrentFetchCallback?.GitUpdateTipsHandler(str, ref oldId, ref newId, data) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_cred_acquire_cb))]
#endif
        internal static int StaticFetchCredentialHandler(out IntPtr ptr, IntPtr cUrl, IntPtr usernameFromUrl, GitCredentialType credTypes, IntPtr payload)
        {
            ptr = IntPtr.Zero;
            return CurrentFetchCallback?.GitCredentialHandler(out ptr, cUrl, usernameFromUrl, credTypes, payload) ?? 0;
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_transport_certificate_check_cb))]
#endif
        internal static unsafe int StaticFetchCertificateCheck(git_certificate* certPtr, int valid, IntPtr cHostname, IntPtr payload)
            => CurrentFetchCallback?.GitCertificateCheck(certPtr, valid, cHostname, payload) ?? 0;
        #endregion


        #region Static Push Callbacks
        static RemoteCallbacks CurrentPushCallback;
#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_push_transfer_progress))]
#endif
        internal static int StaticPushTransferProgressHandler(uint current, uint total, UIntPtr bytes, IntPtr payload)
            => CurrentPushCallback?.GitPushTransferProgressHandler(current, total, bytes, payload) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_packbuilder_progress))]
#endif
        internal static int StaticPushPackbuilderProgressHandler(int stage, uint current, uint total, IntPtr payload)
            => CurrentPushCallback?.GitPackbuilderProgressHandler(stage, current, total, payload) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_cred_acquire_cb))]
#endif
        internal static int StaticPushCredentialHandler(out IntPtr ptr, IntPtr cUrl, IntPtr usernameFromUrl, GitCredentialType credTypes, IntPtr payload)
        {
            ptr = IntPtr.Zero;
            return CurrentPushCallback?.GitCredentialHandler(out ptr, cUrl, usernameFromUrl, credTypes, payload) ?? 0;
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_transport_certificate_check_cb))]
#endif
        internal static unsafe int StaticPushCertificateCheck(git_certificate* certPtr, int valid, IntPtr cHostname, IntPtr payload)
            => CurrentPushCallback?.GitCertificateCheck(certPtr, valid, cHostname, payload) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.push_update_reference_callback))]
#endif
        internal static int StaticPushUpdateReference(IntPtr str, IntPtr status, IntPtr data)
            => CurrentPushCallback?.GitPushUpdateReference(str, status, data) ?? 0;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.push_negotiation_callback))]
#endif
        internal static int StaticPushNegotiationHandler(IntPtr updates, UIntPtr len, IntPtr payload)
            => CurrentPushCallback?.GitPushNegotiationHandler(updates, len, payload) ?? 0;
        #endregion


        #region Static CredentialsHandler Callbacks
        static RemoteCallbacks CurrentCredientialsCallback;

#if __IOS__
        [MonoPInvokeCallback(typeof(NativeMethods.git_cred_acquire_cb))]
#endif
        internal static int StaticCredentialHandler(out IntPtr ptr, IntPtr cUrl, IntPtr usernameFromUrl, GitCredentialType credTypes, IntPtr payload)
        {
            ptr = IntPtr.Zero;
            return CurrentPushCallback?.GitCredentialHandler(out ptr, cUrl, usernameFromUrl, credTypes, payload) ?? 0;
        }

        #endregion

#pragma warning restore CA1416

        #region Constructors
        private RemoteCallbacks(CredentialsHandler credentialsProvider)
        {
            CredentialsProvider = credentialsProvider;
        }

        private RemoteCallbacks(PushOptions pushOptions)
        {
            if (pushOptions == null)
            {
                return;
            }

            PushTransferProgress = pushOptions.OnPushTransferProgress;
            PackBuilderProgress = pushOptions.OnPackBuilderProgress;
            CredentialsProvider = pushOptions.CredentialsProvider;
            CertificateCheck = pushOptions.CertificateCheck;
            PushStatusError = pushOptions.OnPushStatusError;
            PrePushCallback = pushOptions.OnNegotiationCompletedBeforePush;
        }

        private RemoteCallbacks(FetchOptionsBase fetchOptions)
        {
            if (fetchOptions == null)
            {
                return;
            }

            Progress = fetchOptions.OnProgress;
            DownloadTransferProgress = fetchOptions.OnTransferProgress;
            UpdateTips = fetchOptions.OnUpdateTips;
            CredentialsProvider = fetchOptions.CredentialsProvider;
            CertificateCheck = fetchOptions.CertificateCheck;
        }
        #endregion


        #region Delegates

        /// <summary>
        /// Progress callback. Corresponds to libgit2 progress callback.
        /// </summary>
        private readonly ProgressHandler Progress;

        /// <summary>
        /// UpdateTips callback. Corresponds to libgit2 update_tips callback.
        /// </summary>
        private readonly UpdateTipsHandler UpdateTips;

        /// <summary>
        /// PushStatusError callback. It will be called when the libgit2 push_update_reference returns a non null status message,
        /// which means that the update was rejected by the remote server.
        /// </summary>
        private readonly PushStatusErrorHandler PushStatusError;

        /// <summary>
        /// Managed delegate to be called in response to a git_transfer_progress_callback callback from libgit2.
        /// This will in turn call the user provided delegate.
        /// </summary>
        private readonly TransferProgressHandler DownloadTransferProgress;

        /// <summary>
        /// Push transfer progress callback.
        /// </summary>
        private readonly PushTransferProgressHandler PushTransferProgress;

        /// <summary>
        /// Pack builder creation progress callback.
        /// </summary>
        private readonly PackBuilderProgressHandler PackBuilderProgress;

        /// <summary>
        /// Called during remote push operation after negotiation, before upload
        /// </summary>
        private readonly PrePushHandler PrePushCallback;

        #endregion

        /// <summary>
        /// The credentials to use for authentication.
        /// </summary>
        private readonly CredentialsHandler CredentialsProvider;

        /// <summary>
        /// Callback to perform validation on the certificate
        /// </summary>
        private readonly CertificateCheckHandler CertificateCheck;


        internal static unsafe GitRemoteCallbacks GenerateCallbacks(CredentialsHandler credentialsProvider)
        {
            var callbacks = new GitRemoteCallbacks { version = 1 };
            CurrentCredientialsCallback = new RemoteCallbacks(credentialsProvider);
            callbacks.acquire_credentials = StaticCredentialHandler;
            return callbacks;
        }

        internal static unsafe GitRemoteCallbacks GenerateCallbacks(PushOptions pushOptions)
        {
            var callbacks = new GitRemoteCallbacks { version = 1 };
            CurrentPushCallback = new RemoteCallbacks(pushOptions);
            if (CurrentPushCallback?.PushTransferProgress != null)
                callbacks.push_transfer_progress = StaticPushTransferProgressHandler;
            if (CurrentPushCallback?.PackBuilderProgress != null)
                callbacks.pack_progress = StaticPushPackbuilderProgressHandler;
            if (CurrentPushCallback?.CredentialsProvider != null)
                callbacks.acquire_credentials = StaticPushCredentialHandler;
            if (CurrentPushCallback?.CertificateCheck != null)
                callbacks.certificate_check = StaticPushCertificateCheck;
            if (CurrentPushCallback?.PushStatusError != null)
                callbacks.push_update_reference = StaticPushUpdateReference;
            if (CurrentPushCallback?.PrePushCallback != null)
                callbacks.push_negotiation = StaticPushNegotiationHandler;
            return callbacks;
        }

        internal static unsafe GitRemoteCallbacks GenerateCallbacks(FetchOptionsBase fetchOptions)
        {
            var callbacks = new GitRemoteCallbacks { version = 1 };
            CurrentFetchCallback = new RemoteCallbacks(fetchOptions);
            if (CurrentFetchCallback?.Progress != null)
                callbacks.progress = StaticFetchProgressHandler;
            if (CurrentFetchCallback?.DownloadTransferProgress != null)
                callbacks.download_progress = StaticFetchDownloadTransferProgressHandler;
            if (CurrentFetchCallback?.UpdateTips != null)
                callbacks.update_tips = StaticFetchUpdateTipsHandler;
            if (CurrentFetchCallback?.CredentialsProvider != null)
                callbacks.acquire_credentials = StaticFetchCredentialHandler;
            if (CurrentFetchCallback?.CertificateCheck != null)
                callbacks.certificate_check = StaticFetchCertificateCheck;
            return callbacks;
        }

        internal unsafe GitRemoteCallbacks GenerateCallbacks()
        {
            var callbacks = new GitRemoteCallbacks { version = 1 };

            if (Progress != null)
            {
                callbacks.progress = GitProgressHandler;
            }

            if (UpdateTips != null)
            {
                callbacks.update_tips = GitUpdateTipsHandler;
            }

            if (PushStatusError != null)
            {
                callbacks.push_update_reference = GitPushUpdateReference;
            }

            if (CredentialsProvider != null)
            {
                callbacks.acquire_credentials = GitCredentialHandler;
            }

            if (CertificateCheck != null)
            {
                callbacks.certificate_check = GitCertificateCheck;
            }

            if (DownloadTransferProgress != null)
            {
                callbacks.download_progress = GitDownloadTransferProgressHandler;
            }

            if (PushTransferProgress != null)
            {
                callbacks.push_transfer_progress = GitPushTransferProgressHandler;
            }

            if (PackBuilderProgress != null)
            {
                callbacks.pack_progress = GitPackbuilderProgressHandler;
            }

            if (PrePushCallback != null)
            {
                callbacks.push_negotiation = GitPushNegotiationHandler;
            }

            return callbacks;
        }

        #region Handlers to respond to callbacks raised by libgit2

        /// <summary>
        /// Handler for libgit2 Progress callback. Converts values
        /// received from libgit2 callback to more suitable types
        /// and calls delegate provided by LibGit2Sharp consumer.
        /// </summary>
        /// <param name="str">IntPtr to string from libgit2</param>
        /// <param name="len">length of string</param>
        /// <param name="data">IntPtr to optional payload passed back to the callback.</param>
        /// <returns>0 on success; a negative value to abort the process.</returns>
        private int GitProgressHandler(IntPtr str, int len, IntPtr data)
        {
            ProgressHandler onProgress = Progress;

            bool shouldContinue = true;

            if (onProgress != null)
            {
                string message = LaxUtf8Marshaler.FromNative(str, len);
                shouldContinue = onProgress(message);
            }

            return Proxy.ConvertResultToCancelFlag(shouldContinue);
        }

        /// <summary>
        /// Handler for libgit2 update_tips callback. Converts values
        /// received from libgit2 callback to more suitable types
        /// and calls delegate provided by LibGit2Sharp consumer.
        /// </summary>
        /// <param name="str">IntPtr to string</param>
        /// <param name="oldId">Old reference ID</param>
        /// <param name="newId">New referene ID</param>
        /// <param name="data">IntPtr to optional payload passed back to the callback.</param>
        /// <returns>0 on success; a negative value to abort the process.</returns>
        private int GitUpdateTipsHandler(IntPtr str, ref GitOid oldId, ref GitOid newId, IntPtr data)
        {
            UpdateTipsHandler onUpdateTips = UpdateTips;
            bool shouldContinue = true;

            if (onUpdateTips != null)
            {
                string refName = LaxUtf8Marshaler.FromNative(str);
                shouldContinue = onUpdateTips(refName, oldId, newId);
            }

            return Proxy.ConvertResultToCancelFlag(shouldContinue);
        }

        /// <summary>
        /// The delegate with the signature that matches the native push_update_reference function's signature
        /// </summary>
        /// <param name="str">IntPtr to string, the name of the reference</param>
        /// <param name="status">IntPtr to string, the update status message</param>
        /// <param name="data">IntPtr to optional payload passed back to the callback.</param>
        /// <returns>0 on success; a negative value to abort the process.</returns>
        private int GitPushUpdateReference(IntPtr str, IntPtr status, IntPtr data)
        {
            PushStatusErrorHandler onPushError = PushStatusError;

            if (onPushError != null)
            {
                string reference = LaxUtf8Marshaler.FromNative(str);
                string message = LaxUtf8Marshaler.FromNative(status);
                if (message != null)
                {
                    onPushError(new PushStatusError(reference, message));
                }
            }

            return Proxy.ConvertResultToCancelFlag(true);
        }

        /// <summary>
        /// The delegate with the signature that matches the native git_transfer_progress_callback function's signature.
        /// </summary>
        /// <param name="progress"><see cref="GitTransferProgress"/> structure containing progress information.</param>
        /// <param name="payload">Payload data.</param>
        /// <returns>the result of the wrapped <see cref="TransferProgressHandler"/></returns>
        private int GitDownloadTransferProgressHandler(ref GitTransferProgress progress, IntPtr payload)
        {
            bool shouldContinue = true;

            if (DownloadTransferProgress != null)
            {
                shouldContinue = DownloadTransferProgress(new TransferProgress(progress));
            }

            return Proxy.ConvertResultToCancelFlag(shouldContinue);
        }

        private int GitPushTransferProgressHandler(uint current, uint total, UIntPtr bytes, IntPtr payload)
        {
            bool shouldContinue = true;

            if (PushTransferProgress != null)
            {
                shouldContinue = PushTransferProgress((int)current, (int)total, (long)bytes);
            }

            return Proxy.ConvertResultToCancelFlag(shouldContinue);
        }

        private int GitPackbuilderProgressHandler(int stage, uint current, uint total, IntPtr payload)
        {
            bool shouldContinue = true;

            if (PackBuilderProgress != null)
            {
                shouldContinue = PackBuilderProgress((PackBuilderStage)stage, (int)current, (int)total);
            }

            return Proxy.ConvertResultToCancelFlag(shouldContinue);
        }

        private int GitCredentialHandler(
            out IntPtr ptr,
            IntPtr cUrl,
            IntPtr usernameFromUrl,
            GitCredentialType credTypes,
            IntPtr payload)
        {
            string url = LaxUtf8Marshaler.FromNative(cUrl);
            string username = LaxUtf8Marshaler.FromNative(usernameFromUrl);

            SupportedCredentialTypes types = default(SupportedCredentialTypes);
            if (credTypes.HasFlag(GitCredentialType.UserPassPlaintext))
            {
                types |= SupportedCredentialTypes.UsernamePassword;
            }
            if (credTypes.HasFlag(GitCredentialType.Default))
            {
                types |= SupportedCredentialTypes.Default;
            }

            ptr = IntPtr.Zero;
            try
            {
                var cred = CredentialsProvider(url, username, types);
                if (cred == null)
                {
                    return (int)GitErrorCode.PassThrough;
                }
                return cred.GitCredentialHandler(out ptr);
            }
            catch (Exception exception)
            {
                Proxy.git_error_set_str(GitErrorCategory.Callback, exception);
                return (int)GitErrorCode.Error;
            }
        }

        private unsafe int GitCertificateCheck(git_certificate* certPtr, int valid, IntPtr cHostname, IntPtr payload)
        {
            string hostname = LaxUtf8Marshaler.FromNative(cHostname);
            Certificate cert = null;

            switch (certPtr->type)
            {
                case GitCertificateType.X509:
                    cert = new CertificateX509((git_certificate_x509*) certPtr);
                    break;
                case GitCertificateType.Hostkey:
                    cert = new CertificateSsh((git_certificate_ssh*) certPtr);
                    break;
            }

            bool result = false;
            try
            {
                result = CertificateCheck(cert, valid != 0, hostname);
            }
            catch (Exception exception)
            {
                Proxy.git_error_set_str(GitErrorCategory.Callback, exception);
            }

            return Proxy.ConvertResultToCancelFlag(result);
        }

        private int GitPushNegotiationHandler(IntPtr updates, UIntPtr len, IntPtr payload)
        {
            if (updates == IntPtr.Zero)
            {
                return (int)GitErrorCode.Error;
            }

            bool result = false;
            try
            {

                int length = len.ConvertToInt();
                PushUpdate[] pushUpdates = new PushUpdate[length];

                unsafe
                {
                    IntPtr* ptr = (IntPtr*)updates.ToPointer();

                    for (int i = 0; i < length; i++)
                    {
                        if (ptr[i] == IntPtr.Zero)
                        {
                            throw new NullReferenceException("Unexpected null git_push_update pointer was encountered");
                        }

                        PushUpdate pushUpdate = new PushUpdate((git_push_update*) ptr[i].ToPointer());
                        pushUpdates[i] = pushUpdate;
                    }

                    result = PrePushCallback(pushUpdates);
                }
            }
            catch (Exception exception)
            {
                Log.Write(LogLevel.Error, exception.ToString());
                Proxy.git_error_set_str(GitErrorCategory.Callback, exception);
                result = false;
            }

            return Proxy.ConvertResultToCancelFlag(result);
        }

        #endregion
    }
}
