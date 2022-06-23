package com.phenom.etg.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class TokenIntrospectionTest {

    @InjectMocks
    TokenIntrospection tokenIntrospection;
    String authorization = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJIX3VGRTloVHQ1R1p1QndxY09wSkZCR1ZzcU9aY2VlYjFvMXNsRTFFUm9rIn0.eyJleHAiOjE2NTA0NjAwMTUsImlhdCI6MTY1MDQ1MjgxNSwianRpIjoiMWE3MWE4NWQtZjg1ZC00MzVkLTlhNmQtYTYzMWQzNTAzZTNkIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLWRldi5waGVub21wcm8uY29tL2F1dGgvcmVhbG1zL1BoZW5vbVRlc3RQYXJ0bmVyMyIsImF1ZCI6WyJvbmVwaGVub20tYXBpIiwiYWNjb3VudCJdLCJzdWIiOiIxNzRmNGEyMy1iYTJlLTRhNDQtODE5Ni1iYjc1OTk0NjJjZDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJlY2YtYXBpIiwic2Vzc2lvbl9zdGF0ZSI6ImQ4Nzg2NTNmLTYwMTQtNGUxNy04NDE4LWE1NTNkNmI2YjhhZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9kZXYtZWNmLXVpLnBoZW5vbXByby5jb20iLCJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJodHRwczovL2Rldi1lY2YtZGF0YS1zZXJ2aWNlLnBoZW5vbXByby5jb20iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJvbmVwaGVub20tYXBpIjp7InJvbGVzIjpbIkNvbmZpZyBBZG1pbiJdfSwiZWNmLWFwaSI6eyJyb2xlcyI6WyJVc2VyIiwiQWRtaW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHBoZW5vbV90ZW5hbnRzIHBoZW5vbV9wcm9maWxlIHBoZW5vbV9yb2xlcyBwaGVub21fZW1haWwgcGhlbm9tX3Bob25lIiwibmFtZSI6IlNvdW15YWRlZXAgUm95IiwidXNlckRldGFpbHMiOnsiaWQiOiIxNzRmNGEyMy1iYTJlLTRhNDQtODE5Ni1iYjc1OTk0NjJjZDgiLCJ1c2VyTmFtZSI6InNvdW15YWRlZXAucm95QHBoZW5vbXBlb3BsZS5jb20ifX0.Qt47TqM_pCxzQWzxq-4yUy2T9P3MZRAxhEdAjQgidONoo_TQikNEuBpAoySxMwHuhUZ3kqXGLzjvJRXbGR_mtJ6yeORl9xZW881cGfl5TwGZqE-v8hgVfSnBDSrerbZlMIdK_ZGcVqpyUViT7dTU9vZ_NAdZBVJSS8sNQF5QFaY76pFYns8KD-cZgcd_6Yymoaqk5vApG3pIlzKMXqhYwMBhoPvpsSoiyXw_LnX0d4l8fysgwkL34JnXC-W3rRuMTUU88GmVwiFe-XsxZuIsz3vKh6BOctKIDpAc4_8pKltawnVPiZGzqB2uUw28Uu4b6zbdKgFXNZ24HQEJIJhMUQ";
    String authorization2 = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkhfdUZFOWhUdDVHWnVCd3FjT3BKRkJHVnNxT1pjZWViMW8xc2xFMUVSb2sifQ.eyJleHAiOjE2NTA0NjAwMTUsImlhdCI6MTY1MDQ1MjgxNSwianRpIjoiMWE3MWE4NWQtZjg1ZC00MzVkLTlhNmQtYTYzMWQzNTAzZTNkIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLWRldi5waGVub21wcm8uY29tL2F1dGgvcmVhbG1zL1BoZW5vbVRlc3RQYXJ0bmVyMyIsImF1ZCI6WyJvbmVwaGVub20tYXBpIiwiYWNjb3VudCJdLCJzdWIiOiIxNzRmNGEyMy1iYTJlLTRhNDQtODE5Ni1iYjc1OTk0NjJjZDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJlY2YtYXBpIiwic2Vzc2lvbl9zdGF0ZSI6ImQ4Nzg2NTNmLTYwMTQtNGUxNy04NDE4LWE1NTNkNmI2YjhhZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9kZXYtZWNmLXVpLnBoZW5vbXByby5jb20iLCJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJodHRwczovL2Rldi1lY2YtZGF0YS1zZXJ2aWNlLnBoZW5vbXByby5jb20iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJvbmVwaGVub20tYXBpIjp7InJvbGVzIjpbIkNvbmZpZyBBZG1pbiJdfSwiZWNmLWFwaSI6eyJyb2xlcyI6WyJVc2VyIiwiQWRtaW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHBoZW5vbV90ZW5hbnRzIHBoZW5vbV9wcm9maWxlIHBoZW5vbV9yb2xlcyBwaGVub21fZW1haWwgcGhlbm9tX3Bob25lIiwibmFtZSI6IlNvdW15YWRlZXAgUm95IiwidXNlcnNEZXRhaWxzIjp7ImlkIjoiMTc0ZjRhMjMtYmEyZS00YTQ0LTgxOTYtYmI3NTk5NDYyY2Q4IiwidXNlck5hbWUiOiJzb3VteWFkZWVwLnJveUBwaGVub21wZW9wbGUuY29tIn19.wlgRXKzKPgyDRxnPXCcl1pgCEuSF4bOyCbOnJD844172JbX4QhMyv5dQ8_iM8rF-0BpPTJbo71nUQhUdj83WlhyIh3rMlrM-UUCh4oR2UtyR3ukuGj-trxhXf_AaFDGGtM4i2S2e0n2cRko2GkJWEtwaW7G6mo3DS5-ZlRXhkCPld13TyssF9HBHETGgvIn2pJn9ukF9QiMIv473k5p_s0XhOpWEAqQ70ty9ca-fyCMQO5_gTKJlxOxFwKA8UNvjitlRcvQ8JPphNFjD5eg7SFWPyu_Fdp-hbp80xa-0VG-sSjwucrJ7J7w9DhIjr4MxddZHV8zvZhFxpW9261dWPg";
    String authorization3 = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxZGlrdW1LT2dWSHhRTXQ2QmZrZnFPc1Z4TXJPM1ZPall4a3VfTUNCSHBRIn0.eyJleHAiOjE2NTM5OTc3OTcsImlhdCI6MTY1Mzk5NDE5NywianRpIjoiMDFiYTM0ZWUtYjYyMC00OThlLThhOGYtZGQ5Zjk3NzNlZTBkIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLXFhLnBoZW5vbXByby5jb20vYXV0aC9yZWFsbXMvUGhlbm9tIiwiYXVkIjpbIm9uZXBoZW5vbS1hcGkiLCJpeC1jb25maWctYXBpIiwiY2FuZGlkYXRlLWFwcCIsInRpcGFhcy1hcGkiLCJhY2NvdW50IiwiY3J5cHRvLWtleW1hbmFnZW1lbnQtYXBpIl0sInN1YiI6IjM2YTg0MjIxLTAyMGEtNDYzZS1iZDNlLTAxODI0MDIwNDdmMiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVjZi1hcGkiLCJzZXNzaW9uX3N0YXRlIjoiODRkOTAzYTgtZDFlMy00OTU2LThlNjctYWMwMDYzNzQ1MjA1IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2VjZi11aS5wcm9kaW4ucGhlbm9tLmNvbSIsImh0dHBzOi8vZWNmLXVpLnByb2RjYS5waGVub20uY29tIiwiaHR0cHM6Ly9lY2YtdWkucHJvZC5waGVub20uY29tIiwiaHR0cHM6Ly9xYS1lY2YtdWkucGhlbm9tcHJvLmNvbSIsImh0dHBzOi8vcWEtZWNmLWRhdGEtc2VydmljZS5waGVub21wcm8uY29tIiwiaHR0cDovL3FhLWVjZi1kYXRhLXNlcnZpY2UuYXdzLnBoZW5vbS5sb2NhbCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImh0dHBzOi8vZWNmLXVpLnN0Z2luLnBoZW5vbXByby5jb20iLCJodHRwczovL2VjZi11aS5zdGcucGhlbm9tcHJvLmNvbSIsImh0dHBzOi8vZWNmLXVpLnN0Z2NhLnBoZW5vbXByby5jb20iLCJodHRwczovL2VjZi11aS5zdGdpci5waGVub21wcm8uY29tIiwiaHR0cHM6Ly9kZXYtZWNmLXVpLnBoZW5vbXByby5jb20iLCJodHRwczovL2VjZi11aS5wcm9kaXIucGhlbm9tLmNvbSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7Im9uZXBoZW5vbS1hcGkiOnsicm9sZXMiOlsiQ29uZmlnIEFkbWluIl19LCJpeC1jb25maWctYXBpIjp7InJvbGVzIjpbIklYLVVzZXIiXX0sImNhbmRpZGF0ZS1hcHAiOnsicm9sZXMiOlsiQUkgU291cmNpbmciXX0sInRpcGFhcy1hcGkiOnsicm9sZXMiOlsiVXNlciJdfSwiZWNmLWFwaSI6eyJyb2xlcyI6WyJVc2VyIiwiQWRtaW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfSwiY3J5cHRvLWtleW1hbmFnZW1lbnQtYXBpIjp7InJvbGVzIjpbInN1cGVyX2FkbWluIl19fSwic2NvcGUiOiJvcGVuaWQgcGhlbm9tX3RlbmFudHMgcGhlbm9tX3Bob25lIHBoZW5vbV9yb2xlcyBwaGVub21fZW1haWwgcGhlbm9tX3Byb2ZpbGUiLCJlbnRpdGxlbWVudHMiOlsiQUxMIl0sIm5hbWUiOiJTb3VteWFkZWVwIFJveSIsInVzZXJEZXRhaWxzIjp7ImlkIjoiMzZhODQyMjEtMDIwYS00NjNlLWJkM2UtMDE4MjQwMjA0N2YyIiwidXNlck5hbWUiOiJzb3VteWFkZWVwLnJveUBwaGVub21wZW9wbGUuY29tIn19.aVucQjyMBOWAKyjnLDmNd1aGvdllVgG81Zs0bhAX33GBKHBNqsX_OZO9xC3NY00tsQsRIJ255qxxFxuAz2JiVOtPADzIHya621XqA-dm4FCPyxJE-6wWguHYru7TFvqOt2D1nRHdR3v3S-i4N9jDHxhn0mgkyd16k9s82XXOolf2nWiV24YIa7Rqq9NnQ8O6JvOerRBdV98CJrkTiIDdDvqDXpmw9feLv3CtD3baySY5M9AjiKd1YQCcCz0mhHvRv3Ndp_qCinyVgHlH6uUxXVv6Ko_PsrnW9e0IXXwGPvLC7-1jSEraQOSrf3PpAr25AGvcyypy8mVd5JWOFjJ6BQ";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    void getUserInformationInternalTest() {
        String userId = tokenIntrospection.getUserId(authorization);
        assertEquals("174f4a23-ba2e-4a44-8196-bb7599462cd8", userId);
    }

    @Test
    void getUserInformationInternal2Test() {
        String userId = tokenIntrospection.getUserId(authorization2);
        assertEquals("UserId not found", userId);
    }

    @Test
    void getUserInformationInternal3Test() {
        List<String> entitlement = tokenIntrospection.getEntitlement(authorization3);
        assertEquals("ALL", entitlement.get(0));
    }

    @Test
    void getUserInformationInternal4Test() {
        boolean isResourceAvailable = tokenIntrospection.isResourceAvailable(authorization);
        assertTrue(isResourceAvailable);
    }

    @Test
    void getUserInformationInternalExceptionTest() {
        try {
            String userName = tokenIntrospection.getUserId("authorization");
        } catch (Exception e) {
            assertEquals(IllegalArgumentException.class, e);
        }
    }

    @Test
    void isValidRequestTest() {
        assertTrue(tokenIntrospection.isClientRequestValid(authorization3, "CIHIGLOBAL"));
    }
}