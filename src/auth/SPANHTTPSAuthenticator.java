package auth;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class SPANHTTPSAuthenticator {

	static {
		System.setProperty("javax.net.debug", "all");
	}

	static class MyAuthenticator extends Authenticator {
		@Override
		public PasswordAuthentication getPasswordAuthentication() {
			System.out.println("Host - " + getRequestingHost());
			System.out.println("Port - " + getRequestingPort());
			System.out.println("Prompt - " + getRequestingPrompt());
			System.out.println("Protocol - " + getRequestingProtocol());
			System.out.println("Scheme - " + getRequestingScheme());
			System.out.println("Site - " + getRequestingSite());
			System.out.println("URL - " + getRequestingURL());
			return new PasswordAuthentication("thanujkumar_sc", "".toCharArray());
		}
	}

	public static void main(String[] args) throws Exception {
		Authenticator.setDefault(new MyAuthenticator());
		URL url = new URL("https://helpdesk.spanservices.com/");
		URLConnection urlCon = url.openConnection();
		TrustModifier.relaxHostAccess(urlCon);
		InputStream ins = urlCon.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(ins));
		String str;
		while ((str = reader.readLine()) != null) {
			System.out.println(str);
		}

		reader.close();
		ins.close();

	}
}


//////////////////////////CUSTOM HOST NAME VERFICATION AND CERTIFICATE ////////////////////////////
class TrustModifier {

	private static SSLSocketFactory factory;

	private static final class TrustingHostNameVerifier implements
			HostnameVerifier {

		@Override
		public boolean verify(String hostname, SSLSession session) {
			System.out.println(getClass() + " - hostname - " + hostname);
			System.out.println(getClass() + " - session - " + session);
			return true;
		}
	}// End of inner class

	private static final class AlwaysTrustManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}

	}

	public static void relaxHostAccess(URLConnection connection) throws KeyManagementException, NoSuchAlgorithmException {
		if (connection instanceof HttpsURLConnection) {
			HttpsURLConnection https = (HttpsURLConnection) connection;
			SSLSocketFactory f = getSSLSocketFactory(https);
			https.setSSLSocketFactory(f);
			https.setHostnameVerifier(new TrustingHostNameVerifier());
		}
	}

	private static synchronized SSLSocketFactory getSSLSocketFactory(
			HttpsURLConnection con) throws KeyManagementException, NoSuchAlgorithmException {
		if (factory == null) {
			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(null, new TrustManager[] { new AlwaysTrustManager() },
					new SecureRandom());
			factory = ctx.getSocketFactory();
		}
		return factory;
	}
}