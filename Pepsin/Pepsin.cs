/*
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
using System.Linq;
using System.Text;
using System.Threading.Tasks;



namespace Pepsin
{
    /// <summary>
    /// Pepsin is a middleware that implements Digest Auth without using Microsoft Active Directory
    /// for projetcts based on httpListeners. Simply pass it the HttpListenerContext obtained with
    /// HttpListener.GetContext() method and pepsin will either accept, deny or respond back in order 
    /// to authenticate the request. 
    /// </summary>
    class Pepsin
    {
        // All the availables realms for this digester.
        private Dictionary<string, string> m_realms;
        // All nonces. A nonce can either have a have a "Transit" status or an "Accepted" status
        // Once a nonce is accepeted, it cannot be reused and is considered sealed (this is to
        // prevent repeat attacks).
        private Dictionary<string, string> m_nonces;
        // usernames and password. Stored in plaintext due to the way MD5 computes the answer.
        private Dictionary<string, string> m_users;
        // list of realms accesssible by a certain user.
        private Dictionary<string, string[]> m_userRealms;

        // Httplistener given to the pepsin instance to send challenge before returning an 
        // authenticated request. 
        private System.Net.HttpListener m_listener;

        /// <summary>
        /// Add a registered user to the server's whitelist. By default a new user doesn't have any realms
        /// </summary>
        /// <param name="username">desired username</param>
        /// <param name="password">password (in plaintext)</param>
        public void addUser(string username, string password)
        {

        }

        public void removeUser(string username)
        {

        }

        public void changePassword(string username, string newPassword)
        {

        }

        public void addRealm(string realm)
        {

        }

        public void removeRealm(string realm)
        {

        }

        public void addPermission(string user, string[] desiredRealms)
        {

        }

        Pepsin(System.Net.HttpListener listener)
        {
            m_listener = listener;
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
                string digestHeader = craftDigestHeader(System.Environment.MachineName, "1234");
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
            }




            // The request could not be authenticated. No further tries are possible. 
            return null;
        }

        private string craftDigestHeader(string desiredRealm, string nonce)
        {
            string response = "Digest realm=\"Login to " + desiredRealm + "\"";
            response += ",qop = \"auth\",nonce = \"";
            response += nonce;
            response += "\", opaque = \"\", stale = \"false\"";

            return response;
        }

        private Dictionary<string, string> parseHeader(string authenticateHeader)
        {
            Dictionary<string, string> paramMap = new Dictionary<string, string>();

            authenticateHeader = authenticateHeader.Trim(new Char[] { '"' });

            string[] authenticateParams = authenticateHeader.Split(',');

            foreach (string element in authenticateParams)
            {
                string[] insertedElem = element.Split('=');
                // First we must remove "Digest" at the beginning of Digest username

                if (insertedElem[0].Equals("Digest username"))
                {
                    insertedElem[0] = "username";
                }

                paramMap.Add(insertedElem[0], insertedElem[1]);

            }

            return paramMap;
        }


    }
}

