using ECorredores.Entidad.Seguridad;
using System;
using System.Collections.Generic;
using System.Text;
using ECorredores.Entidad.Param;
using ECorredores.Entidad.Administracion;
using ECorredores.Entidad.Config.Correo;
using ECorredores.Servicio.Config;
using ECorredores.Servicio.Shared;
using System.Linq;
using System.Security.Cryptography;
using System.IO;

namespace ECorredores.Servicio.Seguridad
{
   public class clsLogin
    {
        private readonly IClienteHttp _cliente;
        public string xError;
        public bool bError;
        private readonly clsManagerArchivos _manegerArchivos;
        private readonly clsCorreos _clienteCorreo;
        public clsLogin()
        {
            _cliente = new ClienteHttp();
            _manegerArchivos = new clsManagerArchivos();
            _clienteCorreo = new clsCorreos();
        }

        public List<InicioSesion> Login(ParamInicioSesion prmInicioSesion)
        {
            var resp = _cliente.PostAsync<InicioSesion, ParamInicioSesion>("api/Seguridad/Login", prmInicioSesion);
            bError = _cliente.bError;
            xError = _cliente.Error;
            return resp;
        }

        public List<UsuarioRespuesta> ReestablecerContrasena(string Login,string Contrasena,int CodAplicacion, bool ReestablecerClave)
        {
            var resp = _cliente.GetAsync<UsuarioRespuesta>($"api/Seguridad/ReestablecerContrasena?Login={Login}&Contrasena={Contrasena}&codAplicacion={CodAplicacion}&ReestablecerClave={ReestablecerClave}");
            bError = _cliente.bError;
            xError = _cliente.Error;
            return resp;
        }

        public CorreoEnvioResultado CorreoRecuperarPass(string UrlCambioClave, string webRootPath,string Login,string Nombre)
        {
            var variables = new Dictionary<string, object>();
            string RutaPlantilla = ConfigAppJson.ObtenerValor("RutaPlantillaRecuperacionClave");
            string rutaplantillasCorreo = @$"{webRootPath}{RutaPlantilla}";
            string NombreEquipo = Environment.MachineName;
            var _ambientes = Variables._AMBIENTES;

            string ambiente = "";

            ambiente = _ambientes.ToList().FirstOrDefault(x =>x.Key.Contains(NombreEquipo)).Value;

            variables.Add("[[AMBIENTE]]", ambiente ?? "AMBIENTE LOCAL" );
            variables.Add("[[APLICACION]]", "eCorredor");            
            variables.Add("[[USAURIO_FULL_NOMBRE]]", Nombre);            
            variables.Add("[[LINK]]", UrlCambioClave);

            var mensajeCorreo = new MensajeCorreo
            {
                asunto = $"Solicitud de cambio de clave eCorredor",
                destinatario = Login
            };
            mensajeCorreo.mensaje = _manegerArchivos.LeerPlantilla(rutaplantillasCorreo, variables);
            var resultadoEnvio = _clienteCorreo.EnviarCorreo(mensajeCorreo);
            return resultadoEnvio;


        }

        public string GenerarToken(string Emain)
        {
            string Token = Guid.NewGuid().ToString();
            var resp = _cliente.GetAsync<TokenRespuesta>($"api/Seguridad/InsertarToken?Emain={Emain}&Token={Token}");
            bError = _cliente.bError;
            xError = _cliente.Error;
            if (resp[0].CodRespuesta == 1)
                return Token;
            return string.Empty;
        }

        public List<TokenRespuesta> ValidarToken(string Token)
        {
            var resp = _cliente.GetAsync<TokenRespuesta>($"api/Seguridad/ValidarToken?Token={Token}");
            bError = _cliente.bError;
            xError = _cliente.Error;
            return resp;
        }

        public List<TokenRespuesta> ConfirmarToken(string Token)
        {
            var resp = _cliente.GetAsync<TokenRespuesta>($"api/Seguridad/ConfirmarToken?Token={Token}");
            bError = _cliente.bError;
            xError = _cliente.Error;
            return resp;
        }

        private static int LLAVEPRIVADA = 0;
        private static int LLAVEPUBLICA = 1;
        public string ObtenerLlave(int Tipo)
        {
            var resp = _cliente.GetAsync<LlaveRespuesta>($"api/Seguridad/ObtenerLlave?Tipo={Tipo}");
            bError = _cliente.bError;
            xError = _cliente.Error;
            if (resp != null && resp.Count > 0 && !string.IsNullOrEmpty(resp[0].Llave))
                return resp[0].Llave;
            return string.Empty;
        }


        public string Encrypt(string data)
        {
            /*
             *CODIGO PARA GENERAR LAS LLAVES* 
             *No es necesario volverlo a ejecutar porque las llaves fueron generadas*
             string url_PublicKey = ConfigAppJson.ObtenerValor("url_PublicKey");
             string url_PrivateKey = ConfigAppJson.ObtenerValor("url_PrivateKey");
             RsaHelper.GenerateRsaKeyPair(url_PrivateKey, url_PublicKey);
            */

            string Key = ObtenerLlave(LLAVEPUBLICA);
            var output = encriptar(Encoding.UTF8.GetBytes(data), Key);
            return ByteArrayToString(output);
        }

        public string Decrypt(string data)
        {
            string Key = ObtenerLlave(LLAVEPRIVADA);
            var output = desencriptar(StringToByteArray(data), Key);
            return Encoding.UTF8.GetString(output);
        }

        private static byte[] encriptar(byte[] input, string pathKey)
        {
            byte[] encrypted;
            using (var rsa = RsaHelper.PublicKeyFromString(pathKey))
            {
                encrypted = rsa.Encrypt(input, true);
            }
            return encrypted;
        }

        private static byte[] desencriptar(byte[] input, string pathKey)
        {
            byte[] encrypted;
            using (var rsa = RsaHelper.PrivateKeyFromString(pathKey))
            {
                encrypted = rsa.Decrypt(input, true);
            }
            return encrypted;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
