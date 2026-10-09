package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.Image
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** AMOLED startup shown while the local encrypted history is initialized. */
@Composable
fun SpDecodeSplashScreen(){
    Box(
        Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding(),
        contentAlignment=Alignment.Center,
    ){
        Column(
            Modifier.fillMaxWidth().padding(horizontal=24.dp),
            horizontalAlignment=Alignment.CenterHorizontally
        ) {
            Box(Modifier.size(116.dp).background(
                Color(0xFF242424),RoundedCornerShape(28.dp)),
                contentAlignment=Alignment.Center) {
                Image(
                    painter=painterResource(R.drawable.ic_launcher_foreground),
                    contentDescription=stringResource(R.string.app_name),
                    modifier=Modifier.size(102.dp),
                )
            }
            Spacer(Modifier.height(24.dp))
            Text(stringResource(R.string.app_name),
                color=Color.White,fontSize=29.sp,fontWeight=FontWeight.Bold,
                textAlign=TextAlign.Center)
            Spacer(Modifier.height(10.dp))
            Text(stringResource(R.string.subtitle),
                color=Color(0xFFABABAB),fontSize=14.sp,
                textAlign=TextAlign.Center)
            Spacer(Modifier.height(36.dp))
            CircularProgressIndicator(color=Color.White,
                strokeWidth=2.dp,modifier=Modifier.size(23.dp))
        }
        // Independent bottom alignment: attribution never sits near the logo
        // and stays above gesture navigation on small screens.
        Text(
            stringResource(R.string.splash_powered_by),
            color=Color(0xFFABABAB),fontSize=12.sp,
            textAlign=TextAlign.Center,
            modifier=Modifier.align(Alignment.BottomCenter)
                .padding(start=20.dp,end=20.dp,bottom=30.dp),
        )
    }
}
