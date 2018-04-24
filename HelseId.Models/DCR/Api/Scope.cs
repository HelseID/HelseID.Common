﻿using System.Collections.Generic;
using Newtonsoft.Json;

namespace HelseId.Models.DCR.Api
{
    public class Scope
    {
        [JsonProperty("name")] public string Name { get; set; }

        [JsonProperty("user_claims")] public IEnumerable<string> UserClaims { get; set; }
    }
}