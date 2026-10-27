package com.example.ui.auth

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import com.example.R
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import com.google.firebase.Firebase
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.auth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

object GoogleSignInHelper {
    private const val TAG = "GoogleSignInHelper"
    private const val DEFAULT_FALLBACK_CLIENT_ID = "862067017915-k252kl4hk0m9dkl38trdto2mn98o4lil.apps.googleusercontent.com"

    private fun getClientId(context: Context): String {
        return try {
            val resId = context.resources.getIdentifier("default_web_client_id", "string", context.packageName)
            if (resId != 0) {
                val str = context.getString(resId)
                if (str.isNotBlank()) str else DEFAULT_FALLBACK_CLIENT_ID
            } else {
                DEFAULT_FALLBACK_CLIENT_ID
            }
        } catch (_: Exception) {
            DEFAULT_FALLBACK_CLIENT_ID
        }
    }

    private fun Context.findActivity(): Activity? {
        var ctx = this
        while (ctx is android.content.ContextWrapper) {
            if (ctx is Activity) return ctx
            ctx = ctx.baseContext
        }
        return null
    }

    fun onGoogleSignInClicked(
        context: Context,
        credentialManager: CredentialManager,
        scope: CoroutineScope,
        onAccountSelected: (email: String, displayName: String, photoUrl: String, idToken: String) -> Unit,
        onAuthSuccess: () -> Unit,
        onAuthError: (String) -> Unit,
        onAuthCancelled: () -> Unit = {}
    ) {
        val activity = context.findActivity()
        if (activity == null) {
            Log.e(TAG, "Activity not found in context")
            onAuthError("Unable to locate Activity for sign-in")
            return
        }

        val clientId = getClientId(context)
        val signInOption = GetSignInWithGoogleOption.Builder(serverClientId = clientId).build()
        val googleIdOption = GetGoogleIdOption.Builder()
            .setServerClientId(clientId)
            .setFilterByAuthorizedAccounts(false)
            .setAutoSelectEnabled(false)
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(signInOption)
            .addCredentialOption(googleIdOption)
            .build()

        scope.launch {
            try {
                val result = credentialManager.getCredential(activity, request)
                val credential = result.credential
                if (credential is CustomCredential && credential.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    val googleIdCred = GoogleIdTokenCredential.createFrom(credential.data)
                    val email = googleIdCred.id
                    val displayName = googleIdCred.displayName ?: email.substringBefore("@")
                    val photoUrl = googleIdCred.profilePictureUri?.toString() ?: ""
                    val idToken = googleIdCred.idToken

                    // Notify UI immediately so the selected account is visible right away
                    onAccountSelected(email, displayName, photoUrl, idToken)

                    try {
                        val authCredential = GoogleAuthProvider.getCredential(idToken, null)
                        Firebase.auth.signInWithCredential(authCredential).await()
                        Log.d(TAG, "Google Sign-In success in Firebase: ${Firebase.auth.currentUser?.email}")
                    } catch (e: Exception) {
                        Log.w(TAG, "Firebase credential sync note: ${e.message}")
                    }
                    onAuthSuccess()
                } else {
                    onAuthError("Unexpected credential format received")
                }
            } catch (e: GetCredentialCancellationException) {
                Log.w(TAG, "Google Sign-In flow cancelled or dismissed: ${e.message}", e)
                onAuthCancelled()
            } catch (e: Exception) {
                Log.e(TAG, "Google Sign-In failed", e)
                onAuthError(e.localizedMessage ?: "Sign-in failed")
            }
        }
    }

    fun attemptAutoSignIn(
        context: Context,
        credentialManager: CredentialManager,
        scope: CoroutineScope,
        onAccountSelected: (email: String, displayName: String, photoUrl: String, idToken: String) -> Unit,
        onAuthSuccess: () -> Unit,
        onUnauthenticated: () -> Unit
    ) {
        val firebaseUser = Firebase.auth.currentUser
        if (firebaseUser != null) {
            val email = firebaseUser.email ?: "user@google.com"
            val name = firebaseUser.displayName ?: email.substringBefore("@")
            val photo = firebaseUser.photoUrl?.toString() ?: ""
            onAccountSelected(email, name, photo, "")
            onAuthSuccess()
            return
        }

        val clientId = getClientId(context)
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(true)
            .setServerClientId(clientId)
            .setAutoSelectEnabled(true)
            .build()

        val request = GetCredentialRequest.Builder().addCredentialOption(googleIdOption).build()

        scope.launch {
            try {
                val result = credentialManager.getCredential(context, request)
                val credential = result.credential
                if (credential is CustomCredential && credential.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    val googleIdCred = GoogleIdTokenCredential.createFrom(credential.data)
                    val email = googleIdCred.id
                    val displayName = googleIdCred.displayName ?: email.substringBefore("@")
                    val photoUrl = googleIdCred.profilePictureUri?.toString() ?: ""
                    val idToken = googleIdCred.idToken

                    onAccountSelected(email, displayName, photoUrl, idToken)

                    try {
                        val authCredential = GoogleAuthProvider.getCredential(idToken, null)
                        Firebase.auth.signInWithCredential(authCredential).await()
                    } catch (_: Exception) {}
                    onAuthSuccess()
                } else {
                    onUnauthenticated()
                }
            } catch (_: Exception) {
                onUnauthenticated()
            }
        }
    }

    fun signOut(
        context: Context,
        credentialManager: CredentialManager,
        scope: CoroutineScope,
        onSignOutComplete: () -> Unit
    ) {
        try {
            Firebase.auth.signOut()
        } catch (_: Exception) {}
        scope.launch {
            try {
                credentialManager.clearCredentialState(ClearCredentialStateRequest())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to clear credential state", e)
            } finally {
                onSignOutComplete()
            }
        }
    }
}
