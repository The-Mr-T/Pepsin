﻿/*
 * MIT License
 *
 * Copyright (c) 2017 Laurent Tremblay
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Collections.Generic;
using System.Text;



namespace Digest
{

    /// <summary>
    /// State of the nonce. Sent = The nonce has been sent to a client, Retired = The nonce has been used in a successfull auth. 
    /// It can't be re-used. 
    /// </summary>
    enum NonceState { Sent, Retired };


    /// <summary>
    /// Pepsin is a middleware that implements Digest Auth without using Microsoft Active Directory.
    /// </summary>
    /// Simply pass it the HttpListenerContext obtained with
    /// HttpListener.GetContext() method and Pepsin will either accept, deny or respond back in order 
    /// to authenticate the request. 
    /// 
    /// Pepsin can either return the context of a valid request, intercept the request and respond to 
    /// it in order to challenge it or return null in case it's impossible for Pepsin to authenticate it.
    class Pepsin
    {
        // All the availables realms for this digester.
        private Dictionary<string, string> m_realms;


        // All nonces. A nonce can either have a have a "Transit" status or an "Accepted" status
        // Once a nonce is accepeted, it cannot be reused and is considered sealed (this is to
        // prevent repeat attacks).
        private Dictionary<string, string> m_nonces;


        
        public enum PasswordType { PlainText, Hashed };
        public struct Password
        {
            public PasswordType type;
            public string content;
        }
        
        private Dictionary<string, Password> m_users;


        // list of realms accesssible by a certain user.
        private Dictionary<string, string[]> m_userRealms;

        // Httplistener given to the pepsin instance to send challenge before returning an 
        // authenticated request. 
        private System.Net.HttpListener m_listener;

        private System.Security.Cryptography.MD5Cng m_MD5Encoder;

        /// <summary>
        /// Add a registered user to the server's whitelist. By default a new user doesn't have any realms
        /// </summary>
        /// <param name="username">desired username</param>
        /// <param name="password">password (in plaintext)</param>
        public void addUser(string username, string password)
        {
            if (!m_users.ContainsKey(username))
            {
                Password pass;
                pass.type = PasswordType.PlainText;
                pass.content = password;
                m_users.Add(username, pass);
            }
            else { throw new ArgumentException(); }
        }

        public void addUserH(string username, string passwordH)
        {
            if (!m_users.ContainsKey(username))
            {
                Password pass;
                pass.type = PasswordType.Hashed;
                pass.content = generateHash(username, passwordH);
                m_users.Add(username, pass);
            }
            else { throw new ArgumentException(); }
        }

        public void removeUser(string username)
        {
            
            if (m_users.ContainsKey(username)) { m_users.Remove(username); } else throw new ArgumentException();
            
        }
        
        public void changePassword(string username, string newPassword)
        {
            if (m_users.ContainsKey(username))
            {
                Password pass;
                pass.content = newPassword;
                pass.type = PasswordType.PlainText;
                m_users.Remove(username);
                m_users.Add(username, pass);
            }
            else { throw new ArgumentException(); }
        }

        public void changePasswordH(string username, string newPassword)
        {
            if (m_users.ContainsKey(username))
            {
                Password pass;
                pass.content = newPassword;
                pass.type = PasswordType.Hashed;
                m_users.Remove(username);
                m_users.Add(username, pass);
            }
            else { throw new ArgumentException(); }
        }

        public void addRealm(string realm)
        {
            // Only a collection of realms, no attached value for now. 
            m_realms.Add(realm, "");
        }

        public void removeRealm(string realm)
        {
            if (m_realms.ContainsKey(realm))
            {
                m_realms.Remove(realm);
            }
            else { throw new ArgumentException(); }
            
        }

        public void addPermission(string user, string[] desiredRealms)
        {
            if (m_users.ContainsKey(user))
            {
                if(m_realms.ContainsKey(desiredRealms[0]))
                {
                    m_userRealms.Add(user, desiredRealms);
                }
            }
            else { throw new ArgumentException();  }
        }

        public Pepsin(System.Net.HttpListener listener)
        {
            m_listener = listener;

            m_nonces = new Dictionary<string, string>();
            m_realms = new Dictionary<string, string>();
            m_userRealms = new Dictionary<string, string[]>();
            m_users = new Dictionary<string, Password>();

            m_MD5Encoder = new System.Security.Cryptography.MD5Cng();
        }

        /// <summary>
        /// Will either accept, challenge or return an unauthorize request context. Will use the HttpListener
        /// provided in constructor in order to interract directly with the client.
        /// </summary>
        /// <param name="context">The context of the request to authenticate</param>
        /// <returns></returns>
        public System.Net.HttpListenerContext digest(System.Net.HttpListenerContext context)
        {
            if (context.Request.Headers["Authorization"] == null)
            {
                string responseString = "<HTML><HEAD><TITLE>Error</TITLE><META HTTP-EQUIV=\"Content - Type\" CONTENT=\"text / html; charset = ISO - 8859 - 1\"></HEAD><BODY><H1>401 Unauthorized.</H1></BODY></HTML>";
                System.Net.HttpListenerResponse response = context.Response;
                // Construct a response.
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                response.StatusCode = 401;
                string digestHeader = craftDigestHeader(System.Environment.MachineName, GenerateNonce());
                response.AddHeader("WWW-Authenticate", digestHeader);
                // Get a response stream and write the response to it.
                response.ContentLength64 = buffer.Length;
                System.IO.Stream output = response.OutputStream;
                output.Write(buffer, 0, buffer.Length);
                // You must close the output stream.
                output.Close();

                // The challenge has been sent. This request was invalid. 
                return null;
            }

            else // An Authorization header was present, there is digest data to analyse. 
            {
                Dictionary<string, string> requestParams = parseHeader(context.Request.Headers["Authorization"]);

                string username = requestParams["username"];

                Console.WriteLine(requestParams["realm"]);
                Console.WriteLine(m_users[username]);
                string clientHA1StringData;
                if (m_users[username].type == PasswordType.PlainText)
                {
                    clientHA1StringData = username + ":" + requestParams["realm"] + ":" + m_users[username];
                }
                else
                {
                    clientHA1StringData = m_users[username].content;
                }

                Console.WriteLine("HA1 = M(" + clientHA1StringData + ")");

                string clientHA2StringData = context.Request.HttpMethod.ToUpper() + ":" + requestParams["uri"];

                Console.WriteLine("HA2 = M(" + clientHA2StringData + ")");

                byte[] clientHA1 = m_MD5Encoder.ComputeHash(System.Text.Encoding.ASCII.GetBytes(clientHA1StringData));
                byte[] clientHA2 = m_MD5Encoder.ComputeHash(System.Text.Encoding.ASCII.GetBytes(clientHA2StringData));

                string clientHA1String = BitConverter.ToString(clientHA1);
                clientHA1String = clientHA1String.ToLower();
                clientHA1String = clientHA1String.Replace("-", String.Empty);

                string clientHA2String = BitConverter.ToString(clientHA2);
                clientHA2String = clientHA2String.ToLower();
                clientHA2String = clientHA2String.Replace("-", String.Empty);

                string clientResponseString = clientHA1String + ":" + requestParams["nonce"] + ":" + requestParams["nc"] + ":" + requestParams["cnonce"] + ":" + requestParams["qop"] + ":" + clientHA2String;

                Console.WriteLine("Final Hash = M(" + clientResponseString + ")");

                byte[] clientResponseHA = m_MD5Encoder.ComputeHash(System.Text.Encoding.ASCII.GetBytes(clientResponseString));
                string clientResponseStringHA = BitConverter.ToString(clientResponseHA);

                clientResponseStringHA = clientResponseStringHA.ToLower();
                clientResponseStringHA = clientResponseStringHA.Replace("-", String.Empty);

                Console.WriteLine("[DIGEST] - Server Hash : " + clientResponseStringHA);
                Console.WriteLine("[DIGEST] - Client Hash : " + requestParams["response"]);

                // ... request was properly authorized
                if (clientResponseStringHA.Equals(requestParams["response"]))
                {
                    return context;
                }

                else
                {
                    return null;
                }

            }

        }

        private string craftDigestHeader(string desiredRealm, string nonce)
        {
            string response = "Digest realm=\"Login to " + desiredRealm + "\"";
            response += ",qop = \"auth\",nonce = \"";
            response += nonce;
            response += "\", opaque = \"\", stale = \"false\"";

            return response;
        }

        private string generateHash(string username, string password)
        {
            string clientHA1StringData = username + ":" + System.Environment.MachineName + ":" + password;

            byte[] clientHA1 = m_MD5Encoder.ComputeHash(System.Text.Encoding.ASCII.GetBytes(clientHA1StringData));

            string clientHA1String = BitConverter.ToString(clientHA1);
            clientHA1String = clientHA1String.ToLower();
            clientHA1String = clientHA1String.Replace("-", String.Empty);

            return clientHA1String;
        }

        private Dictionary<string, string> parseHeader(string authenticateHeader)
        {
            Dictionary<string, string> paramMap = new Dictionary<string, string>();
            Console.WriteLine("Header before : " + authenticateHeader);
            authenticateHeader = authenticateHeader.Replace("\"", String.Empty);

            Console.WriteLine("Header after : " + authenticateHeader);
            string[] authenticateParams = authenticateHeader.Split(',');

            foreach (string element in authenticateParams)
            {
                string[] insertedElem = element.Split('=');

                // Concatenate path if "=" char is present. 
                if (insertedElem.Length > 2)
                {
                    for (int i = 2; i < insertedElem.Length; i++)
                    {
                        insertedElem[1] += "=" + insertedElem[i];
                    }
                }

                // First we must remove "Digest" at the beginning of Digest username
                if (insertedElem[0].Equals("Digest username"))
                {
                    insertedElem[0] = "username";
                }

                insertedElem[0] = insertedElem[0].Trim();

                paramMap.Add(insertedElem[0], insertedElem[1]);

            }

            return paramMap;
        }

        /// <summary>
        /// Generates a 32 character lowercase hexadecimal nonce. 
        /// </summary>
        /// <returns>32 character lowercase hexadecimal nonce</returns>
        private string GenerateNonce()
        {
            return Guid.NewGuid().ToString("N");
        }

    }
}