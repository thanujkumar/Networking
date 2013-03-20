package auth;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;

public class Tomcat7Authenticato {

	static class MyAuthenticator extends Authenticator {
		@Override
		public PasswordAuthentication getPasswordAuthentication() {
			System.out.println("Host - "+getRequestingHost());
			System.out.println("Port - "+getRequestingPort());
			System.out.println("Prompt - "+getRequestingPrompt());
			System.out.println("Protocol - "+getRequestingProtocol());
			System.out.println("Scheme - "+getRequestingScheme());
			System.out.println("Site - "+getRequestingSite());
			System.out.println("URL - "+getRequestingURL());
			return new PasswordAuthentication("admin", "admin".toCharArray());
		}
	}

	
	public static void main(String[] args) throws Exception {
		Authenticator.setDefault(new MyAuthenticator());
		URL url = new URL("http://localhost:8080/manager/html");
		InputStream ins = url.openConnection().getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(ins));
		String str;
        while((str = reader.readLine()) != null) {
            System.out.println(str);
        }
        
        reader.close();
        ins.close();

	}
}
