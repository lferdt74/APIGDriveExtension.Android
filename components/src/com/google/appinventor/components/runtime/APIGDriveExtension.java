package com.APIGDriveExtension;
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2014-2018 HJLDevelosmen, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

import android.net.Uri;
import android.webkit.MimeTypeMap;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.googleapis.services.GoogleKeyInitializer;
import com.google.api.client.googleapis.services.AbstractGoogleClient;
//import com.google.api.client.googleapis.services.json.AbstractGoogleJsonClient;
import com.google.api.client.googleapis.media.MediaHttpDownloader;
import com.google.api.client.googleapis.media.MediaHttpUploader;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;

import com.google.api.services.fusiontables.Fusiontables;
import com.google.api.services.fusiontables.Fusiontables.Query.Sql;
 
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.extensions.android2.AndroidHttp;

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.GenericUrl;

import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;

import com.google.api.client.util.Preconditions;
import com.google.api.client.util.Sets;
import com.google.api.client.util.store.*;	
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.client.util.ObjectParser;
import com.google.api.client.util.*;

import com.google.appinventor.components.runtime.*;
import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.annotations.UsesPermissions;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.common.YaVersion;
import com.google.appinventor.components.runtime.util.ClientLoginHelper;
import com.google.appinventor.components.runtime.util.ErrorMessages;
import com.google.appinventor.components.runtime.util.IClientLoginHelper;
import com.google.appinventor.components.runtime.util.MediaUtil;
import com.google.appinventor.components.runtime.util.OAuth2Helper;
import com.google.appinventor.components.runtime.util.SdkLevel;

import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.drive.model.ParentReference;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.util.Log;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
//import java.io.File;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import com.google.common.io.Files;
import java.io.*;
import java.lang.Object;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Collection;
import java.util.*;
import java.security.GeneralSecurityException;
import java.io.StringWriter; 
import java.io.PrintWriter;

@DesignerComponent(version = APIGDriveExtension.VERSION,
    description = "Extension JAVA para uso de los servicios de la API de Googgle Drive. " + "Luis Fernando Diaz - HJLDevelosmen ",
    category = ComponentCategory.EXTENSION,
    nonVisible = true,
    iconName = "https://ssl.gstatic.com/docs/doclist/images/drive_icon_32.png")
@SimpleObject(external = true)
//@UsesPermissions(permissionNames = "android.permission.READ_EXTERNAL_STORAGE, android.permission.GET_ACCOUNTS, android.permission.READ_CONTACTS") 
@UsesPermissions(permissionNames =
    "android.permission.INTERNET," +
    "android.permission.ACCOUNT_MANAGER," +
    "android.permission.MANAGE_ACCOUNTS," +
    "android.permission.GET_ACCOUNTS," +
    "android.permission.USE_CREDENTIALS," +
    "android.permission.WRITE_EXTERNAL_STORAGE," +
    "android.permission.READ_EXTERNAL_STORAGE")
@UsesLibraries(libraries =
    "googleapiservicesdrive.jar," +
    "googleapiclient.jar," +
	"googleapiclientjackson2.jar," +
    "google-api-client-android2-beta.jar," +
    "googlehttpclient.jar," +
    "google-http-client-android2-beta.jar," +
    "google-http-client-android3-beta.jar," +
    "google-oauth-client-beta.jar," +
    "guava-14.0.1.jar," +
	"gson-2.1.jar," +
	"googlehttpclientgson.jar," +
    "fasterxmljacksoncore.jar")
//@Value.Style(jdkOnly = true)
//@Value.Immutable	
public class APIGDriveExtension extends AndroidNonvisibleComponent implements Component {
	//Valores default implements Component 
	public static final int VERSION = 1;
	public static final String DEFAULT_APPLICATION_NAME = "";
	public static final String DEFAULT_SCOPE_DRIVE = "https://www.googleapis.com/auth/drive.file";
	public static final String DEFAULT_FOLDER_ID = "";
	public static final String DEFAULT_PRIVATE_KEYID = "";
	public static final String DEFAULT_KEYFILE = "";
	public static final String DEFAULT_USER_SERVICE = "";
	
	//Container 
	private static ComponentContainer container;

	//Variables del programa
	private static String application_name = "";
	private static String serviceaccountid = "";
	private static String serviceaccountprivatekeyid = "";
	private String serviceaccountscope = "https://www.googleapis.com/auth/drive.file";
	private static String folder_id = "";
	private static String client_secret_path = "";
	private static java.io.File cachedServiceCredentials = null; // if using service accounts, temp location of credentials.
	
	/** Global instance of the HTTP transport. private static*/
	private static HttpTransport httpTransport;

	/** Global instance of the JSON factory. private static final*/
	//private static JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
	private static JsonFactory JSON_FACTORY = new GsonFactory();

	/** Global Drive API client. private static */
	private static com.google.api.services.drive.Drive drive;

	// authorization
	//private static com.google.api.client.auth.oauth2.Credential credential;
	private static GoogleCredential credential = null;
	
	//Constructor de la clase para inicializar variables y obtener el contexto de la API de GOOGLE
	public APIGDriveExtension(ComponentContainer container) {
		super(container.$form());
		this.container = container;
		
		Application_Name(DEFAULT_APPLICATION_NAME);
		ServiceAccountPrivateKeyId(DEFAULT_PRIVATE_KEYID);
		ServiceAccountScope(DEFAULT_SCOPE_DRIVE);
		Folder_Id(DEFAULT_FOLDER_ID);
		KeyFile(DEFAULT_KEYFILE);
		ServiceAccountId(DEFAULT_USER_SERVICE);
		
		//httpTransport = GoogleNetHttpTransport.newTrustedTransport();
		//httpTransport = new com.google.api.client.http.javanet.NetHttpTransport();
		httpTransport = AndroidHttp.newCompatibleTransport();
				
		/*
		try {
			
			
		} catch (IOException e) {
			System.err.println(e.getMessage());
		} catch (Throwable t) {
			t.printStackTrace();
		}*/
	}//End Method

	// Creacion de las Propiedades.
	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String Application_Name() {
		return application_name;
	}
	
	
	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String ServiceAccountPrivateKeyId() {
		return serviceaccountprivatekeyid;
	}
	
	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String ServiceAccountScope() {
		return serviceaccountscope;
	}

	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String Folder_Id() {
		return folder_id;
	}
		
	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String KeyFile() {
		return client_secret_path;
	}
		
	@SimpleProperty(
		category = PropertyCategory.BEHAVIOR)
	public String ServiceAccountId() {
		return serviceaccountid;
	}
	
	// Establecimiento de las Propiedades.
	
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_TEXT, defaultValue = APIGDriveExtension.DEFAULT_APPLICATION_NAME + "")
	@SimpleProperty(description = "Nombre de la aplicacion asociada al proyecto. ")
	public void Application_Name(String nuevoApplication_Name) {
		this.application_name = nuevoApplication_Name;
	}
	
	
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_TEXT, defaultValue = APIGDriveExtension.DEFAULT_PRIVATE_KEYID + "")
	@SimpleProperty(description = "Codigo alfanumerico Private Key asociado al certificado del proyecto y necesario para autenticarse en el servicio de drive. ")
	public void ServiceAccountPrivateKeyId(String nuevoServiceAccountPrivateKeyId) {
		this.serviceaccountprivatekeyid = nuevoServiceAccountPrivateKeyId;
	}
	
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_TEXT, defaultValue = APIGDriveExtension.DEFAULT_SCOPE_DRIVE + "")
	@SimpleProperty(description = "SCOPE para acceso al servicio de drive. Normalmente https://www.googleapis.com/auth/drive ")
	public void ServiceAccountScope(String nuevoServiceAccountScope) {
		this.serviceaccountscope = nuevoServiceAccountScope;
	}
	
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_TEXT, defaultValue = APIGDriveExtension.DEFAULT_FOLDER_ID + "")
	@SimpleProperty(description = "ID del folder por defecto del servicio de drive donde se cargaran las imagenes.")
	public void Folder_Id(String nuevoFolder_Id) {
		this.folder_id = nuevoFolder_Id;
	}
	
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_ASSET, defaultValue = "")
	@SimpleProperty(description = "Ruta del Archivo de .p12 necesario para autenticarse en el servicio de drive. ")
	public void KeyFile(String nuevoClient_Secret_Path) {
		//this.client_secret_path = nuevoClient_Secret_Path;
		// If it's the same as on the prior call and the prior load was successful,
		// do nothing.
		if (nuevoClient_Secret_Path.equals(client_secret_path)) {
		  return;
		}

		// Remove old cached credentials if we are changing the client_secret_path
		if (cachedServiceCredentials != null) {
		  cachedServiceCredentials.delete();
		  cachedServiceCredentials = null;
		}
		client_secret_path = (nuevoClient_Secret_Path == null) ? "" : nuevoClient_Secret_Path;
	}
		
	@DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_TEXT, defaultValue = APIGDriveExtension.DEFAULT_USER_SERVICE + "")
	@SimpleProperty(description = "Usuario del servicio Account Service. ")
	public void ServiceAccountId(String nuevoServiceAccountId) {
		this.serviceaccountid = nuevoServiceAccountId;
	}
	
	/**
	 * Return private key from a file. Must be a valid PEM file with PKCS#8 encoding standard.
	 *
	 * @return a private key
	 */
	java.security.PrivateKey loadPrivateKey(java.io.File keyFile) throws IOException, java.security.NoSuchAlgorithmException, java.security.spec.InvalidKeySpecException {
		byte[] content = Files.toByteArray(keyFile);
		java.security.spec.PKCS8EncodedKeySpec ks = new java.security.spec.PKCS8EncodedKeySpec(content);
		return java.security.KeyFactory.getInstance("RSA").generatePrivate(ks);
	}
	
	/**
	 * Obtain an access token.
	 *
	 * GoogleCredential provides an interface for JWT requests.
	 */
	void authorize() throws GeneralSecurityException, IOException, java.security.NoSuchAlgorithmException 
	{
		String strPath = "";
		
		strPath = serviceaccountprivatekeyid + client_secret_path;
		try {
			if (cachedServiceCredentials == null) { // Need to cache the credentials in a temp file
			  // copyMediaToTempFile will copy the credentials either from the /sdcard if
			  // we are running in the Companion, or from the packaged assets if we are a
			  // packaged application.
			  cachedServiceCredentials = new java.io.File(strPath);
			  //MediaUtil.copyMediaToTempFile(container.$form(), strPath);
			}
			GoogleCredential credential = new  GoogleCredential.Builder()
				.setTransport(AndroidHttp.newCompatibleTransport())
				.setJsonFactory(new GsonFactory())
				.setServiceAccountId(serviceaccountid)
				.setServiceAccountScopes(serviceaccountscope)
				.setServiceAccountPrivateKeyFromP12File(cachedServiceCredentials)
				.build();
			
			credential.refreshToken();
			
		} catch (IOException e) {
			// invalidate credential
			credential = null;
		}
	}
	
	/**
	 * Refresh access token.
	 *
	 * GoogleCredential provides an interface for JWT requests.
	 */
	public String getAccessToken() throws GeneralSecurityException, IOException
	{
		try {
			if (credential == null) {
			  authorize();
			}

			// If expired
			if (credential.getExpirationTimeMilliseconds() < new Date().getTime()) {
			  credential.refreshToken();
			}
			return credential.getAccessToken();
		} catch (IOException e) {
			return "UNAUTHORIZED";
		}
	}
	
	/** Autoriza la aplicacion para acceder a los datos protegidos del usuario. */
	@SimpleFunction(description = "Autoriza la aplicacion para acceder a los datos protegidos del usuario.")
	private static GoogleCredential authorize_old() 
		throws GeneralSecurityException, IOException 
	{
		String strResult = "";
		String strPath = "";
		
		strPath = serviceaccountprivatekeyid + client_secret_path;
		//client_secret_path = strPath;
		//Completa la ruta en caso de que el usuario no la envie en las variables de instanciacion del constructor
		// if ( !client_secret_path.startsWith("file://") && !client_secret_path.startsWith("/") ) {
			// client_secret_path = "/" + client_secret_path;
		// }
		// if (!client_secret_path.startsWith("file://")) {
			// client_secret_path = "file://" + client_secret_path;
		// }
		//Controla si la ruta genera un archivo valido
		Uri uri  = Uri.parse(client_secret_path);
		//java.io.File fileSecretCode = new java.io.File(uri.getPath());
		java.io.File fileSecretCode = new java.io.File(strPath);
		if (fileSecretCode.isFile()) 
		{
			try
			{
				/*
				if (cachedServiceCredentials == null) { // Need to cache the credentials in a temp file
					// copyMediaToTempFile will copy the credentials either from the /sdcard if
					// we are running in the Companion, or from the packaged assets if we are a
					// packaged application.
					cachedServiceCredentials = MediaUtil.copyMediaToTempFile(container.$form(), client_secret_path);
				} 
				GoogleCredential credential = new  GoogleCredential.Builder()
						.setTransport(httpTransport)
						.setJsonFactory(JSON_FACTORY)
						.setServiceAccountId(serviceaccountid)
						.setServiceAccountScopes(Collections.singleton(serviceaccountscope))
						.setServiceAccountPrivateKeyFromP12File(cachedServiceCredentials)
						.build();	
				*/

				//java.io.File fileSecretCode = new java.io.File(client_secret_path);
				GoogleCredential credential = new GoogleCredential.Builder()
					.setTransport(httpTransport)
					.setJsonFactory(JSON_FACTORY)
					.setServiceAccountId(serviceaccountid) //emailAddress
					//.setServiceAccountScopes(Collections.singleton(serviceaccountscope))
					.setServiceAccountScopes("")
					.setServiceAccountPrivateKeyFromP12File(new java.io.File(strPath))
					.build();
				credential.refreshToken();
			}
			catch (Throwable t) {
				StringWriter sw = new StringWriter();
				t.printStackTrace(new PrintWriter(sw));
				strResult = "Ocurrio un Error authorize: " + sw.toString();
				System.out.println(strResult);
			}
		}
		else
		{
			throw new IOException("La ruta especificada "+strPath+" no contiene un archivo valido "+fileSecretCode+" .");
		}
		return credential;
	}//End Method
	
	/** Carga archivos tanto en forma resumida como directa. */
	@SimpleFunction(description = "Carga archivos tanto en forma resumida como directa. Si se devuelve un valor que contenga Error significa que fallo el proceso. ")
	public String uploadFile(boolean useDirectUpload, String file_path)  
	{
		String strResult = "";
		com.google.api.services.drive.model.File body = null;
		FileContent mediaContent = null;
		
		try {
			//Completa la ruta en caso de que el usuario no la envie en las variables de instanciacion del constructor
			if (!file_path.startsWith("file://")) {
				file_path = "file://" + file_path;
			}
			//Controla si la ruta genera un archivo valido
			Uri uri  = Uri.parse(file_path);
			java.io.File imageFile = new java.io.File(uri.getPath());
			if (imageFile.isFile()) 
			{
				String fileExtension = file_path.substring(file_path.lastIndexOf(".")+1).toLowerCase();
				MimeTypeMap mime = MimeTypeMap.getSingleton();
				String type = mime.getMimeTypeFromExtension(fileExtension);

				java.io.File UPLOAD_FILE = new java.io.File(file_path);
				String title = UPLOAD_FILE.getName();
				
				ParentReference newParent = new ParentReference();
				newParent.setId(folder_id);
				
				// File metadata.
				body = new com.google.api.services.drive.model.File();
				body.setTitle(title);
				body.setMimeType(type);

				// Set the parent folder.
				if (folder_id != null && folder_id.length() > 0) {
				  body.setParents(
					  Arrays.asList(new ParentReference().setId(folder_id)));
				}

				// File content.
				//java.io.File fileContent = new java.io.File(file_path);
				mediaContent = new FileContent(type, UPLOAD_FILE);
				strResult = "Paso 1";
				
				// authorization and context
				if (getAccessToken() == "UNAUTHORIZED") 
				{
					throw new IOException("Error obteniendo las credenciales de acceso.");
				}
				else
				{
					strResult = "Paso 2";
					
					// set up the global Drive instance
					// Create a Drive service object (from Google API client lib)
					drive = new Drive.Builder(
						httpTransport, JSON_FACTORY, credential)
						//AndroidHttp.newCompatibleTransport()
						//new GsonFactory(),
						//new GoogleCredential())
						.setApplicationName(application_name)
						//.setJsonHttpRequestInitializer(new GoogleKeyInitializer(serviceaccountprivatekeyid))
						.build();
						
					strResult = "Paso 3";
					
					File file = drive.files().insert(body, mediaContent).execute();
					strResult = "Paso 4";
					
					// Uncomment the following line to print the File ID.
					// System.out.println("File ID: " + file.getId());

					strResult = file.getId();
					return strResult;
				}	
			}
			else
			{
				throw new IOException("La ruta especificada "+file_path+" no contiene un archivo valido "+uri.getPath()+" .");
			}
		} catch (IOException e) {
			strResult = strResult + " Ocurrio un Error IOException uploadFile: " + e.getMessage() + " \n." + file_path;
			System.out.println(strResult);
			return strResult;
		}
		catch (Throwable t) {
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			strResult = strResult + " credential"+credential+" cachedServiceCredentials:"+cachedServiceCredentials+"  body:"+body+"  mediaContent:"+mediaContent;
			strResult = strResult + " Ocurrio un Error Throwable uploadFile: " + sw.toString();
			System.out.println(strResult);
			return strResult;
		}
	}//End Method
	
	/** Actualiza el nombre de un archivo ya cargado. */
	@SimpleFunction(description = "Actualiza el nombre de un archivo ya cargado. Si se devuelve un valor que contenga Error significa que fallo el proceso. ")
	public String updateFileWithTestSuffix(String fileId, String title) 
	{
		String strResult = ""; 
		
		try
		{
			File fileMetadata = new File();
			fileMetadata.setTitle(title);

			Drive.Files.Update updater = drive.files().update(fileId, fileMetadata);
			File fileResult = updater.execute();
			strResult = fileResult.getId();
			
			return strResult;
		}
		catch (IOException e) {
			strResult = "Ocurrio un Error: " + e.getMessage();
			System.out.println(strResult);
			return strResult;
		}
		catch (Throwable t) {
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			strResult = "Ocurrio un Error: " + sw.toString();
			System.out.println(strResult);
			return strResult;
		}
	}//End Method

	/** Descarga un archivo en forma resumida o directa partiendo de su ID. */
	@SimpleFunction(description = "Descarga un archivo en forma resumida o directa partiendo de su ID. Si se devuelve un valor que contenga Error significa que fallo el proceso.")
	public String downloadFile(boolean useDirectDownload, String fileId, String file_path)
	{
		String strResult = "";
		
		try
		{
			File uploadedFile = drive.files().get(fileId).execute();
			
			// create parent directory (if necessary)
			java.io.File parentDir = new java.io.File(file_path);
			if (!parentDir.exists() && !parentDir.mkdirs()) {
				throw new IOException("No se puede crear el directorio raiz de descarga.");
			}
			else
			{
				OutputStream out = new FileOutputStream(new java.io.File(parentDir, uploadedFile.getTitle()));

				MediaHttpDownloader downloader =
				//new MediaHttpDownloader(httpTransport, drive.getRequestFactory().getInitializer());
				new MediaHttpDownloader(AndroidHttp.newCompatibleTransport(), drive.getRequestFactory().getInitializer());
				downloader.setDirectDownloadEnabled(useDirectDownload);
				downloader.download(new GenericUrl(uploadedFile.getDownloadUrl()), out);
				strResult = "0";
			}
			
			return strResult;
		} 
		catch (IOException e) {
			strResult = "Ocurrio un Error: " + e.getMessage();
			System.out.println(strResult);
			return strResult;
		}
		catch (Throwable t) {
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			strResult = "Ocurrio un Error: " + sw.toString();
			System.out.println(strResult);
			return strResult;
		}
	}//End Method
}//End Class
